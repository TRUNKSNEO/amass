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
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/general"
)

type horfqdn struct {
	name   string
	plugin *horizPlugin
}

func (h *horfqdn) Name() string {
	return h.name
}

func (h *horfqdn) check(e *et.Event) error {
	fqdn, ok := e.Entity.Asset.(*oamdns.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	if _, conf := e.Session.Scope().IsAssetInScope(fqdn, 0); conf > 0 {
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.FQDN), string(oam.FQDN), h.plugin.name)
	if err != nil {
		return nil
	}

	matches, err := e.Session.Config().CheckTransformations(string(oam.FQDN), string(oam.FQDN), h.plugin.name)
	if err != nil || matches.Len() == 0 {
		return nil
	}

	conf := matches.Confidence(h.plugin.name)
	if conf == -1 {
		conf = matches.Confidence(string(oam.FQDN))
	}

	if assocs := h.lookup(e, e.Entity, conf); len(assocs) > 0 {
		var impacted []*dbt.Entity

		for _, assoc := range assocs {
			if assoc.ScopeChange {
				e.Session.Log().Info(assoc.Rationale)
				impacted = append(impacted, assoc.ImpactedAssets...)
			}
		}

		var assets []*dbt.Entity
		for _, im := range impacted {
			ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
			defer cancel()

			if ents, err := e.Session.DB().FindEntitiesByContent(ctx,
				im.Asset.AssetType(), since, 1, assetToContentFilters(im.Asset)); err == nil {
				assets = append(assets, ents[0])
			} else if n := h.store(e, im.Asset); n != nil {
				assets = append(assets, n)
			}
		}

		if len(assets) > 0 {
			h.plugin.process(e, since, assets)
		}
	}
	return nil
}

func (h *horfqdn) lookup(e *et.Event, asset *dbt.Entity, conf int) []*et.Association {
	assocs, err := e.Session.Scope().IsAssociated(&et.Association{
		Submission:  asset,
		Confidence:  conf,
		ScopeChange: true,
	})
	if err != nil {
		return nil
	}
	return assocs
}

func (h *horfqdn) store(e *et.Event, asset oam.Asset) *dbt.Entity {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 3*time.Second)
	defer cancel()

	a, err := e.Session.DB().CreateAsset(ctx, asset)
	if err != nil || a == nil {
		return nil
	}

	_, _ = e.Session.DB().CreateEntityProperty(ctx, a, &general.SourceProperty{
		Source:     h.plugin.source.Name,
		Confidence: h.plugin.source.Confidence,
	})
	return a
}
