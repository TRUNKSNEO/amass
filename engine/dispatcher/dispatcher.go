// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dispatcher

import (
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	et "github.com/owasp-amass/amass/v5/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
)

type dynamicDispatcher struct {
	log *slog.Logger
	reg et.Registry
	mgr et.SessionManager

	mu    sync.RWMutex
	pools map[oam.AssetType]*pipelinePool
}

func NewDispatcher(l *slog.Logger, r et.Registry, mgr et.SessionManager) et.Dispatcher {
	return &dynamicDispatcher{
		log:   l,
		reg:   r,
		mgr:   mgr,
		pools: make(map[oam.AssetType]*pipelinePool),
	}
}

func (d *dynamicDispatcher) Shutdown() {
	// Optional: add pool-level shutdown if you want explicit draining.
}

func (d *dynamicDispatcher) DispatchEvent(e *et.Event) error {
	if e == nil || e.Entity == nil {
		return nil
	}

	at := inferAssetTypeFromEvent(e)
	pool := d.getOrCreatePool(at)

	return pool.Dispatch(e)
}

func (d *dynamicDispatcher) getOrCreatePool(at oam.AssetType) *pipelinePool {
	d.mu.RLock()
	pool := d.pools[at]
	d.mu.RUnlock()
	if pool != nil {
		return pool
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if pool = d.pools[at]; pool != nil {
		return pool
	}

	// TODO: make these configurable per AssetType
	minInstances := 2
	maxInstances := 16
	pool = newPipelinePool(d.log, d.reg, at, minInstances, maxInstances)
	d.pools[at] = pool
	return pool
}

// inferAssetTypeFromEvent should mirror your current pipeline selection logic.
func inferAssetTypeFromEvent(e *et.Event) oam.AssetType {
	// Pseudo-code; wire this to your entity / OAM data:
	//
	//   return e.Entity.AssetType()
	//
	return 0
}

func (d *dis) maintainPipelines() {
	ctick := time.NewTimer(time.Second)
	defer ctick.Stop()
	mtick := time.NewTimer(10 * time.Second)
	defer mtick.Stop()
loop:
	for {
		select {
		case <-d.done:
			break loop
		case <-mtick.C:
			checkOnTheHeap()
			mtick.Reset(10 * time.Second)
		default:
		}

		select {
		case <-ctick.C:
			d.fillPipelineQueues()
			ctick.Reset(time.Second)
		case e := <-d.dchan:
			if err := d.safeDispatch(e); err != nil {
				d.logger.Error(fmt.Sprintf("Failed to dispatch event: %s", err.Error()))
			}
		case e := <-d.cchan:
			d.completedCallback(e)
		}
	}
}

func (d *dis) fillPipelineQueues() {
	sessions := d.mgr.GetSessions()
	if len(sessions) == 0 {
		return
	}

	var ptypes []oam.AssetType
	for _, atype := range oam.AssetList {
		if ap, err := d.reg.GetPipeline(atype); err == nil {
			if ap.Queue.Len() < MinPipelineQueueSize {
				ptypes = append(ptypes, atype)
			}
		}
	}

	numRequested := MaxPipelineQueueSize / len(sessions)
	for _, s := range sessions {
		if s == nil || s.Done() {
			continue
		}
		for _, atype := range ptypes {
			if entities, err := s.Queue().Next(atype, numRequested); err == nil && len(entities) > 0 {
				for _, entity := range entities {
					e := &et.Event{
						Name:    fmt.Sprintf("%s - %s", string(atype), entity.Asset.Key()),
						Entity:  entity,
						Session: s,
					}
					if err := d.appendToPipeline(e); err != nil {
						d.logger.Error(fmt.Sprintf("Failed to append to a data pipeline: %s", err.Error()))
					}
				}
			}
		}
	}
}

func (d *dis) completedCallback(data interface{}) {
	ede, ok := data.(*et.EventDataElement)
	if !ok {
		return
	}

	if err := ede.Error; err != nil {
		ede.Event.Session.Log().WithGroup("event").With("name", ede.Event.Name).Error(err.Error())
	}
	// increment the number of events processed in the session
	if stats := ede.Event.Session.Stats(); stats != nil {
		stats.Lock()
		stats.WorkItemsCompleted++
		stats.Unlock()
	}
}

func (d *dis) safeDispatch(e *et.Event) error {
	// there is no need to dispatch the event if there's no associated asset pipeline
	if ap, err := d.reg.GetPipeline(e.Entity.Asset.AssetType()); err != nil || ap == nil {
		return err
	}

	// do not schedule the same asset more than once
	if e.Session.Queue().Has(e.Entity) {
		return nil
	}

	err := e.Session.Queue().Append(e.Entity)
	if err != nil {
		return err
	}

	// increment the number of events processed in the session
	if stats := e.Session.Stats(); stats != nil {
		stats.Lock()
		stats.WorkItemsTotal++
		stats.Unlock()
	}

	if e.Meta != nil {
		if err := d.appendToPipeline(e); err != nil {
			d.logger.Error(fmt.Sprintf("Failed to append to a data pipeline: %s", err.Error()))
			return err
		}
	}
	return nil
}

func (d *dis) appendToPipeline(e *et.Event) error {
	if e == nil || e.Session == nil || e.Entity == nil || e.Entity.Asset == nil {
		return errors.New("the event is nil")
	}

	ap, err := d.reg.GetPipeline(e.Entity.Asset.AssetType())
	if err != nil {
		return err
	}

	e.Dispatcher = d
	if data := et.NewEventDataElement(e); data != nil {
		_ = e.Session.Queue().Processed(e.Entity)
		data.Queue = d.cchan
		ap.Queue.Append(data)
	}
	return nil
}
