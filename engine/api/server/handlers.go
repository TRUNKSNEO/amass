// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	oam "github.com/owasp-amass/open-asset-model"
)

const maxBulkItems = 5000

type CreateSessionResponse struct {
	SessionID string    `json:"session_id"`
	Created   time.Time `json:"created_at"`
}

type ListSessionsResponse struct {
	SessionIDs []string `json:"session_ids"`
}

// Bulk typed add: {"items":[ <OAM obj>, <OAM obj>, ... ]}
// where each item is arbitrary JSON object without "type".
type BulkAddAssetsRequest struct {
	Items []json.RawMessage `json:"items"`
}

type BulkAddAssetsResponse struct {
	Ingested int64 `json:"ingested"`
	Stored   int64 `json:"stored"`
	Failed   int64 `json:"failed"`
}

var (
	ErrNotFound   = errors.New("not found")
	ErrBadRequest = errors.New("bad request")
)

func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		s.log.Info("request completed", "method", r.Method, "path", r.URL.Path, "duration", time.Since(start))
	})
}

func (s *Server) createSessionHandler(w http.ResponseWriter, r *http.Request) {
}

func (s *Server) listSessionsHandler(w http.ResponseWriter, r *http.Request) {
	sessions := s.mgr.GetSessions()
	if len(sessions) == 0 {
		writeError(w, http.StatusNotFound, "zero sessions found", ErrNotFound)
		return
	}

	var resp ListSessionsResponse
	for _, sess := range sessions {
		resp.SessionIDs = append(resp.SessionIDs, sess.ID().String())
	}

	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) terminateSessionHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	sid := vars["session_id"]

	// Check if the session token is valid
	token, err := uuid.Parse(sid)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid session token", err)
		return
	}
	// Check if the session exists
	// and if the session is not already terminated
	sess := s.mgr.GetSession(token)
	if sess == nil {
		writeError(w, http.StatusNotFound, "session not found", ErrNotFound)
		return
	}

	go s.mgr.CancelSession(token)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) getStatsHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	sid := vars["session_id"]

	// Check if the session token is valid
	token, err := uuid.Parse(sid)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid session token", err)
		return
	}
	// Check if the session exists
	// and if the session is not already terminated
	sess := s.mgr.GetSession(token)
	if sess == nil {
		writeError(w, http.StatusNotFound, "session not found", ErrNotFound)
		return
	}

	writeJSON(w, http.StatusOK, sess.Stats())
}

// Single typed add: raw OAM JSON in body, asset type in path.
func (s *Server) addAssetTypedHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	sid := vars["session_id"]
	assetType := strings.ToLower(strings.TrimSpace(vars["asset_type"]))

	// Check if the session token is valid
	token, err := uuid.Parse(sid)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid session token", err)
		return
	}
	// Check if the session exists
	// and if the session is not already terminated
	sess := s.mgr.GetSession(token)
	if sess == nil {
		writeError(w, http.StatusNotFound, "session not found", ErrNotFound)
		return
	}

	raw, err := readRawJSON(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON", err)
		return
	}
	// minimal validation: ensure it’s valid JSON object
	if !looksLikeJSONObject(raw) {
		writeError(w, http.StatusBadRequest, "invalid JSON object", nil)
		return
	}

	a, err := parseAsset(assetType, raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid asset object", err)
		return
	}

	if err := s.PutAsset(s.ctx, a); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to submit the asset", err)
		return
	}
	writeJSON(w, http.StatusOK, a)
}

func (s *Server) addAssetsBulkHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	sid := vars["session_id"]
	assetType := strings.ToLower(strings.TrimSpace(vars["asset_type"]))

	// Check if the session token is valid
	token, err := uuid.Parse(sid)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid session token", err)
		return
	}
	// Check if the session exists
	// and if the session is not already terminated
	sess := s.mgr.GetSession(token)
	if sess == nil {
		writeError(w, http.StatusNotFound, "session not found", ErrNotFound)
		return
	}

	var req BulkAddAssetsRequest
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON", err)
		return
	}
	if len(req.Items) == 0 {
		writeError(w, http.StatusBadRequest, "items must be non-empty", nil)
		return
	}
	if len(req.Items) > maxBulkItems {
		writeError(w, http.StatusRequestEntityTooLarge, "too many items in bulk request", errors.New("max items exceeded"))
		return
	}

	recs := make([]oam.Asset, 0, len(req.Items))
	for _, raw := range req.Items {
		// minimal validation: ensure it’s valid JSON object
		if !looksLikeJSONObject(raw) {
			// count as failed ingest, but continue
			continue
		}

		a, err := parseAsset(assetType, raw)
		if err != nil {
			// count as failed ingest, but continue
			continue
		}

		recs = append(recs, a)
	}

	ingested := int64(len(recs))
	if ingested == 0 {
		writeError(w, http.StatusBadRequest, "no valid JSON objects in items", nil)
		return
	}

	stored, err := s.PutAssets(s.ctx, recs)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, BulkAddAssetsResponse{
			Ingested: ingested,
			Stored:   0,
			Failed:   ingested,
		})
		return
	}

	failed := ingested - int64(stored)
	writeJSON(w, http.StatusOK, BulkAddAssetsResponse{
		Ingested: ingested,
		Stored:   int64(stored),
		Failed:   failed,
	})
}
