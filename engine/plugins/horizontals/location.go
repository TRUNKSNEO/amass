// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package horizontals

import (
	"context"
	"errors"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamcert "github.com/owasp-amass/open-asset-model/certificate"
	oamcon "github.com/owasp-amass/open-asset-model/contact"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
)

type horLocation struct {
	name   string
	plugin *horizPlugin
}

func (h *horLocation) Name() string {
	return h.name
}

func (h *horLocation) check(e *et.Event) error {
	_, ok := e.Entity.Asset.(*oamcon.Location)
	if !ok {
		return errors.New("failed to cast the Location asset")
	}

	// check if scope expansion is allowed
	if e.Session.Config().Rigid {
		return nil
	}

	lconf := h.locConfidence(e.Session)
	if lconf <= 0 {
		return nil
	}

	if _, conf := e.Session.Scope().IsAssetInScope(e.Entity.Asset, lconf); conf >= lconf {
		h.processInScope(e)
	} else {
		h.processOutOfScope(e)
	}
	return nil
}

func (h *horLocation) processInScope(e *et.Event) {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), time.Minute)
	defer cancel()

	since, err := support.TTLStartTime(e.Session.Config(),
		string(oam.Location), string(oam.ContactRecord), h.plugin.name)
	if err != nil {
		return
	}

	edges, err := e.Session.DB().IncomingEdges(ctx, e.Entity, since, "location")
	if err != nil || len(edges) == 0 {
		return
	}

	for _, edge := range edges {
		from, err := e.Session.DB().FindEntityById(ctx, edge.FromEntity.ID)
		if err != nil {
			continue
		}
		// add the contact record orgs and locations to the scope
		if orgs, locs := h.plugin.lookupContactRecordOrgsAndLocations(e.Session, from); len(orgs) > 0 || len(locs) > 0 {
			for _, o := range orgs {
				_ = e.Session.Scope().Add(o.Asset)
			}
			for _, loc := range locs {
				_ = e.Session.Scope().Add(loc.Asset)
			}
		}
		// if the contact record belongs to a registration record or TLS certificate, add to the scope
		if edges, err := e.Session.DB().IncomingEdges(ctx, e.Entity, since); err == nil {
			for _, edge := range edges {
				if from, err := e.Session.DB().FindEntityById(ctx, edge.FromEntity.ID); err == nil {
					switch v := from.Asset.(type) {
					case *oamreg.AutnumRecord:
						_ = e.Session.Scope().Add(from.Asset)
						h.plugin.addASNetblocksToScope(e.Session, v.Number)
					case *oamreg.DomainRecord:
						_ = e.Session.Scope().Add(from.Asset)
					case *oamreg.IPNetRecord:
						_ = e.Session.Scope().Add(from.Asset)
					case *oamcert.TLSCertificate:
						_ = e.Session.Scope().Add(from.Asset)
					}
				}
			}
		}
	}
}

func (h *horLocation) processOutOfScope(e *et.Event) {
	assocs, err := e.Session.Scope().IsAssociated(&et.Association{
		Submission:  e.Entity,
		ScopeChange: true,
	})
	if err != nil {
		return
	}

	for _, assoc := range assocs {
		if assoc.ScopeChange {
			e.Session.Log().Info(assoc.Rationale)
		}
	}
}

func (h *horLocation) locConfidence(sess et.Session) int {
	ltype := string(oam.Location)

	if matches, err := sess.Config().CheckTransformations(ltype, ltype); err == nil && matches != nil {
		if conf := matches.Confidence(h.plugin.name); conf > 0 {
			return conf
		}
		if conf := matches.Confidence(ltype); conf > 0 {
			return conf
		}
	}

	return -1
}
