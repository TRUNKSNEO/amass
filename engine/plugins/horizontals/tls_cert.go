// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package horizontals

import (
	"context"
	"errors"
	"time"

	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamcert "github.com/owasp-amass/open-asset-model/certificate"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
)

type horTlsCert struct {
	name   string
	plugin *horizPlugin
}

func (h *horTlsCert) Name() string {
	return h.name
}

func (h *horTlsCert) check(e *et.Event) error {
	c, ok := e.Entity.Asset.(*oamcert.TLSCertificate)
	if !ok {
		return errors.New("failed to cast the TLSCertificate asset")
	}

	// check if scope expansion is allowed
	if e.Session.Config().Rigid {
		return nil
	}

	if orgs, err := h.lookup(e.Session, e.Entity); err == nil && len(orgs) > 0 {
		h.process(e, c, orgs)
	}
	return nil
}

func (h *horTlsCert) lookup(sess et.Session, tlsent *dbt.Entity) ([]*dbt.Entity, error) {
	cr, err := h.plugin.getContactRecord(sess, tlsent, "subject_contact")
	if err != nil {
		return nil, errors.New("failed to obtain the subject contact record")
	}

	orgs, err := h.plugin.getContactRecordOrganizations(sess, cr)
	if err != nil {
		return nil, errors.New("failed to obtain the subject organizations")
	}

	return orgs, nil
}

func (h *horTlsCert) process(e *et.Event, c *oamcert.TLSCertificate, orgs []*dbt.Entity) {
	// check if the TLS certificate subject common name is in scope
	if _, conf := e.Session.Scope().IsAssetInScope(&oamdns.FQDN{Name: c.SubjectCommonName}, 0); conf > 0 {
		for _, o := range orgs {
			_ = e.Session.Scope().Add(o.Asset)
		}
		return
	}

	var confidence int
	otype := string(oam.Organization)
	if matches, err := e.Session.Config().CheckTransformations(otype, otype); err == nil && matches != nil {
		if conf := matches.Confidence(otype); conf >= 0 {
			confidence = conf
		}
	}

	var found bool
	if confidence > 0 {
		for _, o := range orgs {
			if _, conf := e.Session.Scope().IsAssetInScope(o.Asset, confidence); conf >= confidence {
				found = true
				break
			}
		}
	}

	if found {
		// the TLS certificate should be added to the scope and reviewed
		_ = e.Session.Scope().Add(c)
		h.enqueueRegisteredFQDN(e.Session, c)

		for _, o := range orgs {
			_ = e.Session.Scope().Add(o.Asset)
		}
	}
}

func (h *horTlsCert) enqueueRegisteredFQDN(sess et.Session, c *oamcert.TLSCertificate) {
	ctx, cancel := context.WithTimeout(sess.Ctx(), 5*time.Second)
	defer cancel()

	if ents, err := sess.DB().FindEntitiesByContent(ctx, oam.FQDN, time.Time{}, 1, dbt.ContentFilters{
		"name": c.SubjectCommonName,
	}); err == nil && len(ents) == 1 {
		fqdn := ents[0]

		_ = sess.Backlog().Enqueue(fqdn)
	}
}
