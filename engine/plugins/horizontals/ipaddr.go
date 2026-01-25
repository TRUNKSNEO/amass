// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package horizontals

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	"golang.org/x/net/publicsuffix"
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

	since, err := support.TTLStartTime(e.Session.Config(),
		string(oam.IPAddress), string(oam.IPAddress), h.plugin.name)
	if err != nil {
		return nil
	}

	h.checkForPTR(e, ip, since)
	return nil
}

func (h *horaddr) checkForPTR(e *et.Event, ip *oamnet.IPAddress, since time.Time) {
	var inscope bool
	if _, conf := e.Session.Scope().IsAssetInScope(ip, 0); conf > 0 {
		inscope = true
	}

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 10*time.Second)
	defer cancel()

	if ptrs, err := e.Session.DB().OutgoingEdges(ctx, e.Entity, since, "ptr_record"); err == nil && len(ptrs) > 0 {
		for _, ptr := range ptrs {
			to, err := e.Session.DB().FindEntityById(ctx, ptr.ToEntity.ID)
			if err != nil {
				continue
			}

			fqdn, ok := to.Asset.(*oamdns.FQDN)
			if !ok {
				continue
			}

			if inscope {
				if dom, err := publicsuffix.EffectiveTLDPlusOne(fqdn.Name); err == nil && dom != "" {
					if e.Session.Scope().AddDomain(dom) {
						e.Session.Log().Info(fmt.Sprintf("[%s: %s] was added to the session scope", "FQDN", dom))
					}
					h.plugin.submitFQDN(e, dom)
				}
			} else if _, conf := e.Session.Scope().IsAssetInScope(fqdn, 0); conf > 0 {
				if e.Session.Scope().Add(ip) {
					size := 100
					if e.Session.Config().Active {
						size = 250
					}
					support.IPAddressSweep(e, ip, h.plugin.source, size, h.plugin.submitIPAddress)
					e.Session.Log().Info(fmt.Sprintf("[%s: %s] was added to the session scope", ip.AssetType(), ip.Key()))
				}
			}
		}
	}
}
