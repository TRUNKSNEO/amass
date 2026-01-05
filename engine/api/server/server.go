// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
	et "github.com/owasp-amass/amass/v5/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamacct "github.com/owasp-amass/open-asset-model/account"
	oamcert "github.com/owasp-amass/open-asset-model/certificate"
	oamcon "github.com/owasp-amass/open-asset-model/contact"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamfile "github.com/owasp-amass/open-asset-model/file"
	oamfin "github.com/owasp-amass/open-asset-model/financial"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	oamorg "github.com/owasp-amass/open-asset-model/org"
	oampeop "github.com/owasp-amass/open-asset-model/people"
	oamplat "github.com/owasp-amass/open-asset-model/platform"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
	oamurl "github.com/owasp-amass/open-asset-model/url"
)

type Server struct {
	ctx    context.Context
	cancel context.CancelFunc
	log    *slog.Logger
	dis    et.Dispatcher
	mgr    et.SessionManager
	ch     chan struct{}
	srv    *http.Server
}

func NewServer(logger *slog.Logger, d et.Dispatcher, mgr et.SessionManager) *Server {
	r := mux.NewRouter()

	ctx, cancel := context.WithCancel(context.Background())
	srv := &Server{
		ctx:    ctx,
		cancel: cancel,
		log:    logger,
		dis:    d,
		mgr:    mgr,
		ch:     make(chan struct{}),
		srv: &http.Server{
			Addr:         ":4000",
			Handler:      r,
			ReadTimeout:  15 * time.Second,
			WriteTimeout: 15 * time.Second,
			IdleTimeout:  60 * time.Second,
		},
	}

	srv.routes(r)
	return srv
}

func (s *Server) Start() error {
	s.log.Info("Server listening on", "addr", s.srv.Addr)
	err := s.srv.ListenAndServe()

	s.cancel()
	close(s.ch)
	return err
}

func (s *Server) Shutdown() error {
	err := s.srv.Shutdown(s.ctx)

	<-s.ch
	return err
}

// UUID route regex (common RFC 4122 form)
const uuidRE = `[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`

// Asset type route regex (tighten if you have an enum)
const assetTypeRE = `[a-z0-9][a-z0-9_-]{0,63}`

/*
Routes (v1)

POST   /v1/sessions
GET	   /v1/sessions/list
DELETE /v1/sessions/{session_id}
GET    /v1/sessions/{session_id}/stats

POST   /v1/sessions/{session_id}/assets/{asset_type}
POST   /v1/sessions/{session_id}/assets/{asset_type}:bulk

GET    /v1/sessions/{session_id}/ws/logs
*/
func (s *Server) routes(r *mux.Router) {
	r.Use(s.loggingMiddleware)

	r.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "route not found", nil)
	})
	r.MethodNotAllowedHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
	})

	v1 := r.PathPrefix("/v1").Subrouter()

	sessions := v1.PathPrefix("/sessions").Subrouter()
	sessions.HandleFunc("", s.createSessionHandler).Methods(http.MethodPost)
	sessions.HandleFunc("/list", s.listSessionsHandler).Methods(http.MethodGet)

	session := sessions.PathPrefix("/{" + uuidRE + "}").Subrouter()
	session.HandleFunc("", s.terminateSessionHandler).Methods(http.MethodDelete)
	session.HandleFunc("/stats", s.getStatsHandler).Methods(http.MethodGet)
	assets := session.PathPrefix("/assets").Subrouter()

	// Single add: type in path (since OAM payload does not include it)
	assets.HandleFunc("/{"+assetTypeRE+"}", s.addAssetTypedHandler).Methods(http.MethodPost)
	// Bulk add: :bulk suffix
	assets.HandleFunc("/{"+assetTypeRE+"}:bulk", s.addAssetsBulkHandler).Methods(http.MethodPost)

	// WebSocket logs only
	ws := session.PathPrefix("/ws").Subrouter()
	ws.HandleFunc("/logs", s.wsLogsHandler).Methods(http.MethodGet)
}

/* ----------------------------- Helpers ----------------------------- */

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string, err error) {
	type resp struct {
		Error   string `json:"error"`
		Details string `json:"details,omitempty"`
		Code    int    `json:"code"`
	}
	out := resp{Error: msg, Code: status}
	if err != nil {
		out.Details = err.Error()
	}
	writeJSON(w, status, out)
}

func readRawJSON(r *http.Request) (json.RawMessage, error) {
	var raw json.RawMessage
	defer r.Body.Close()

	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&raw); err != nil {
		return nil, err
	}

	if len(raw) == 0 {
		return nil, ErrBadRequest
	}
	return raw, nil
}

func looksLikeJSONObject(raw json.RawMessage) bool {
	s := strings.TrimSpace(string(raw))
	return strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}")
}

func (s *Server) PutAsset(ctx context.Context, rec oam.Asset) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	return nil
}

func (s *Server) PutAssets(ctx context.Context, recs []oam.Asset) (int, error) {
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	default:
	}
	return len(recs), nil
}

func parseAsset(atype string, j json.RawMessage) (oam.Asset, error) {
	switch atype {
	case strings.ToLower(string(oam.Account)):
		var a oamacct.Account
		err := json.Unmarshal(j, &a)
		return &a, err
	case strings.ToLower(string(oam.AutnumRecord)):
		var a oamreg.AutnumRecord
		err := json.Unmarshal(j, &a)
		return &a, err
	case strings.ToLower(string(oam.AutonomousSystem)):
		var a oamnet.AutonomousSystem
		err := json.Unmarshal(j, &a)
		return &a, err
	case strings.ToLower(string(oam.ContactRecord)):
		var a oamcon.ContactRecord
		err := json.Unmarshal(j, &a)
		return &a, err
	case strings.ToLower(string(oam.DomainRecord)):
		var a oamreg.DomainRecord
		err := json.Unmarshal(j, &a)
		return &a, err
	case strings.ToLower(string(oam.File)):
		var a oamfile.File
		err := json.Unmarshal(j, &a)
		return &a, err
	case strings.ToLower(string(oam.FQDN)):
		var a oamdns.FQDN
		err := json.Unmarshal(j, &a)
		return &a, err
	case strings.ToLower(string(oam.FundsTransfer)):
		var a oamfin.FundsTransfer
		err := json.Unmarshal(j, &a)
		return &a, err
	case strings.ToLower(string(oam.Identifier)):
		var a oamgen.Identifier
		err := json.Unmarshal(j, &a)
		return &a, err
	case strings.ToLower(string(oam.IPAddress)):
		var a oamnet.IPAddress
		err := json.Unmarshal(j, &a)
		return &a, err
	case strings.ToLower(string(oam.IPNetRecord)):
		var a oamreg.IPNetRecord
		err := json.Unmarshal(j, &a)
		return &a, err
	case strings.ToLower(string(oam.Location)):
		var a oamcon.Location
		err := json.Unmarshal(j, &a)
		return &a, err
	case strings.ToLower(string(oam.Netblock)):
		var a oamnet.Netblock
		err := json.Unmarshal(j, &a)
		return &a, err
	case strings.ToLower(string(oam.Organization)):
		var a oamorg.Organization
		err := json.Unmarshal(j, &a)
		return &a, err
	case strings.ToLower(string(oam.Phone)):
		var a oamcon.Phone
		err := json.Unmarshal(j, &a)
		return &a, err
	case strings.ToLower(string(oam.Person)):
		var a oampeop.Person
		err := json.Unmarshal(j, &a)
		return &a, err
	case strings.ToLower(string(oam.Product)):
		var a oamplat.Product
		err := json.Unmarshal(j, &a)
		return &a, err
	case strings.ToLower(string(oam.ProductRelease)):
		var a oamplat.ProductRelease
		err := json.Unmarshal(j, &a)
		return &a, err
	case strings.ToLower(string(oam.Service)):
		var a oamplat.Service
		err := json.Unmarshal(j, &a)
		return &a, err
	case strings.ToLower(string(oam.TLSCertificate)):
		var a oamcert.TLSCertificate
		err := json.Unmarshal(j, &a)
		return &a, err
	case strings.ToLower(string(oam.URL)):
		var a oamurl.URL
		err := json.Unmarshal(j, &a)
		return &a, err
	}
	return nil, fmt.Errorf("unknown asset type: %s", atype)
}
