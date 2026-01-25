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
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamnet "github.com/owasp-amass/open-asset-model/network"
)

type horaddr struct {
	name   string
	plugin *horizPlugin
}

func (h *horaddr) Name() string {
	return h.name
}

func (h *horaddr) check(e *et.Event) error {
	ip, ok := e.Entity.Asset.(*oamnet.IPAddress)
	if !ok {
		return errors.New("failed to extract the IPAddress asset")
	}

	if h.checkForPTR(e) {
		h.process(e, ip)
	}
	return nil
}

func (h *horaddr) checkForPTR(e *et.Event) bool {
	since, err := support.TTLStartTime(e.Session.Config(),
		string(oam.IPAddress), string(oam.FQDN), h.plugin.name)
	if err != nil || since.IsZero() {
		return false
	}

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	ptrs, err := e.Session.DB().OutgoingEdges(ctx, e.Entity, since, "ptr_record")
	if err != nil || len(ptrs) == 0 {
		return false
	}

	since, err = support.TTLStartTime(e.Session.Config(),
		string(oam.FQDN), string(oam.FQDN), h.plugin.name)
	if err != nil || since.IsZero() {
		return false
	}

	for _, ptr := range ptrs {
		edges, err := e.Session.DB().OutgoingEdges(ctx, ptr.ToEntity, since, "dns_record")
		if err != nil || len(edges) == 0 {
			continue
		}

		for _, edge := range edges {
			if rel, ok := edge.Relation.(*oamdns.BasicDNSRelation); !ok || rel.Header.RRType != 12 {
				continue
			}

			to, err := e.Session.DB().FindEntityById(ctx, edge.ToEntity.ID)
			if err != nil {
				continue
			}

			if fqdn, valid := to.Asset.(*oamdns.FQDN); valid {
				if _, conf := e.Session.Scope().IsAssetInScope(fqdn, 0); conf > 0 {
					return true
				}
			}
		}
	}

	return false
}

func (h *horaddr) process(e *et.Event, ip *oamnet.IPAddress) {
	size := 100
	if e.Session.Config().Active {
		size = 250
	}

	support.IPAddressSweep(e, ip, h.plugin.source, size, h.plugin.submitIPAddress)
}
