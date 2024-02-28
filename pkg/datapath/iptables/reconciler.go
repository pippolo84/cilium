// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package iptables

import (
	"context"
	"net"
	"net/netip"

	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/stream"
	"github.com/cilium/cilium/pkg/time"
)

type desiredState struct {
	installRules bool

	devices       sets.Set[string]
	localNodeInfo localNodeInfo
	proxies       sets.Set[proxyInfo]
	noTrackPods   sets.Set[noTrackPodInfo]
}

type localNodeInfo struct {
	internalIPv4          net.IP
	internalIPv6          net.IP
	ipv4AllocCIDR         string
	ipv6AllocCIDR         string
	ipv4NativeRoutingCIDR string
	ipv6NativeRoutingCIDR string
}

func (lni localNodeInfo) equal(other localNodeInfo) bool {
	if !lni.internalIPv4.Equal(other.internalIPv4) ||
		!lni.internalIPv6.Equal(other.internalIPv6) ||
		lni.ipv4AllocCIDR != other.ipv4AllocCIDR ||
		lni.ipv6AllocCIDR != other.ipv6AllocCIDR ||
		lni.ipv4NativeRoutingCIDR != other.ipv4NativeRoutingCIDR ||
		lni.ipv6NativeRoutingCIDR != other.ipv6NativeRoutingCIDR {
		return false
	}
	return true
}

func toLocalNodeInfo(n node.LocalNode) localNodeInfo {
	var (
		v4AllocCIDR, v6AllocCIDR                 string
		v4NativeRoutingCIDR, v6NativeRoutingCIDR string
	)

	if n.IPv4AllocCIDR != nil {
		v4AllocCIDR = n.IPv4AllocCIDR.String()
	}
	if n.IPv6AllocCIDR != nil {
		v6AllocCIDR = n.IPv6AllocCIDR.String()
	}
	if n.IPv4NativeRoutingCIDR != nil {
		v4NativeRoutingCIDR = n.IPv4NativeRoutingCIDR.String()
	}
	if n.IPv6NativeRoutingCIDR != nil {
		v6NativeRoutingCIDR = n.IPv6NativeRoutingCIDR.String()
	}

	return localNodeInfo{
		internalIPv4:          n.GetCiliumInternalIP(false),
		internalIPv6:          n.GetCiliumInternalIP(true),
		ipv4AllocCIDR:         v4AllocCIDR,
		ipv6AllocCIDR:         v6AllocCIDR,
		ipv4NativeRoutingCIDR: v4NativeRoutingCIDR,
		ipv6NativeRoutingCIDR: v6NativeRoutingCIDR,
	}
}

type info interface {
	proxyInfo | noTrackPodInfo
}

type reconciliationRequest[T info] struct {
	info T

	// closed when the state is reconciled successfully
	updated chan struct{}
}

type proxyInfo struct {
	name        string
	port        uint16
	isIngress   bool
	isLocalOnly bool
}

type noTrackPodInfo struct {
	ip   netip.Addr
	port uint16
}

func reconciliationLoop(
	ctx context.Context,
	log logrus.FieldLogger,
	health cell.HealthReporter,
	installIptRules bool,
	params *reconcilerParams,
	updateRules func(state desiredState, firstInit bool) error,
	updateProxyRules func(proxyPort uint16, ingress, localOnly bool, name string) error,
	installNoTrackRules func(addr netip.Addr, port uint16) error,
	removeNoTrackRules func(addr netip.Addr, port uint16) error,
) error {
	// The minimum interval between reconciliation attempts
	const minReconciliationInterval = time.Second / 20

	state := desiredState{
		installRules: installIptRules,
		proxies:      sets.New[proxyInfo](),
		noTrackPods:  sets.New[noTrackPodInfo](),
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	localNodeEvents := stream.ToChannel(ctx, params.localNodeStore)
	state.localNodeInfo = toLocalNodeInfo(<-localNodeEvents)

	devices, devicesWatch := tables.SelectedDevices(params.devices, params.db.ReadTxn())
	state.devices = sets.New(tables.DeviceNames(devices)...)

	// Use a ticker to limit how often the desired state is reconciled to avoid doing
	// lots of operations when e.g. ipset updates.
	ticker := time.NewTicker(minReconciliationInterval)
	defer ticker.Stop()

	// stateChanged is true when the desired state has changed or when reconciling it
	// has failed. It's set to false when reconciling succeeds.
	stateChanged := true

	firstInit := true

	// list of pending channels waiting for reconciliation
	var updatedChs []chan<- struct{}

stop:
	for {
		select {
		case <-ctx.Done():
			break stop
		case <-devicesWatch:
			devices, devicesWatch = tables.SelectedDevices(params.devices, params.db.ReadTxn())
			newDevices := sets.New(tables.DeviceNames(devices)...)
			if newDevices.Equal(state.devices) {
				continue
			}
			state.devices = newDevices
			stateChanged = true
		case localNode, ok := <-localNodeEvents:
			if !ok {
				break stop
			}
			localNodeInfo := toLocalNodeInfo(localNode)
			if localNodeInfo.equal(state.localNodeInfo) {
				continue
			}
			state.localNodeInfo = localNodeInfo
			stateChanged = true
		case req, ok := <-params.proxies:
			if !ok {
				break stop
			}
			if state.proxies.Has(req.info) {
				close(req.updated)
				continue
			}

			// first, remove previous entries related to the same proxy name (see Manager.addProxyRules)
			for info := range state.proxies {
				if info.name == req.info.name {
					delete(state.proxies, info)
				}
			}
			// then, insert the new proxy
			state.proxies.Insert(req.info)

			if !firstInit {
				// first init not yet completed, proxy rules will be updated as part of that
				stateChanged = true
				updatedChs = append(updatedChs, req.updated)
				continue
			}

			if err := updateProxyRules(req.info.port, req.info.isIngress, req.info.isLocalOnly, req.info.name); err != nil {
				health.Degraded("iptables proxy rules incremental update failed, will retry a full reconciliation", err)
				// incremental rules update failed, schedule a full iptables reconciliation
				stateChanged = true
				updatedChs = append(updatedChs, req.updated)
			} else {
				health.OK("iptables proxy rules update completed")
				close(req.updated)
			}
		case req, ok := <-params.addNoTrackPod:
			if !ok {
				break stop
			}
			if state.noTrackPods.Has(req.info) {
				close(req.updated)
				continue
			}
			state.noTrackPods.Insert(req.info)

			if !firstInit {
				// first init not yet completed, no track pod rules will be updated as part of that
				stateChanged = true
				updatedChs = append(updatedChs, req.updated)
				continue
			}

			if err := installNoTrackRules(req.info.ip, req.info.port); err != nil {
				health.Degraded("iptables no track rules incremental install failed, will retry a full reconciliation", err)
				// incremental rules update failed, schedule a full iptables reconciliation
				stateChanged = true
				updatedChs = append(updatedChs, req.updated)
			} else {
				health.OK("iptables no track rules update completed")
				close(req.updated)
			}
		case req, ok := <-params.delNoTrackPod:
			if !ok {
				break stop
			}
			if !state.noTrackPods.Has(req.info) {
				close(req.updated)
				continue
			}
			state.noTrackPods.Delete(req.info)

			if !firstInit {
				// first init not yet completed, no track pod rules will be updated as part of that
				stateChanged = true
				updatedChs = append(updatedChs, req.updated)
				continue
			}

			if err := removeNoTrackRules(req.info.ip, req.info.port); err != nil {
				health.Degraded("iptables no track rules incremental removal failed, will retry a full reconciliation", err)
				// incremental rules update failed, schedule a full iptables reconciliation
				stateChanged = true
				updatedChs = append(updatedChs, req.updated)
			} else {
				health.OK("iptables no track rules update completed")
				close(req.updated)
			}
		case <-ticker.C:
			if !stateChanged {
				continue
			}

			if err := updateRules(state, firstInit); err != nil {
				health.Degraded("iptables rules update failed", err)
				// Keep stateChanged=true to try again on the next tick.
			} else {
				health.OK("iptables rules update completed")
				firstInit = false
				stateChanged = false
				// close all channels waiting for reconciliation
				for _, ch := range updatedChs {
					close(ch)
				}
				updatedChs = updatedChs[:0]
			}
		}
	}

	cancel()

	// close all channels waiting for reconciliation
	for _, ch := range updatedChs {
		close(ch)
	}

	// drain channels
	for range localNodeEvents {
	}
	for range params.proxies {
	}
	for range params.addNoTrackPod {
	}
	for range params.delNoTrackPod {
	}

	return nil
}
