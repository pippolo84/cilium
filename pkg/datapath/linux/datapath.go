// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linux

import (
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/datapath/tables"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/loadbalancer/experimental"
	"github.com/cilium/cilium/pkg/maps/lbmap"
	"github.com/cilium/cilium/pkg/maps/nodemap"
	"github.com/cilium/cilium/pkg/node/manager"
	"github.com/cilium/cilium/pkg/testutils/mockmaps"
)

// DatapathConfiguration is the static configuration of the datapath. The
// configuration cannot change throughout the lifetime of a datapath object.
type DatapathConfiguration struct {
	// HostDevice is the name of the device to be used to access the host.
	HostDevice string

	// TunnelDevice is the name of the tunnel device (if any).
	TunnelDevice string
}

type linuxDatapath struct {
	datapath.ConfigWriter
	datapath.IptablesManager
	nodeAddressing datapath.NodeAddressing
	lbmap          datapath.LBMap
	bwmgr          datapath.BandwidthManager
	orchestrator   datapath.Orchestrator
}

type DatapathParams struct {
	ConfigWriter   datapath.ConfigWriter
	RuleManager    datapath.IptablesManager
	NodeMap        nodemap.MapV2
	BWManager      datapath.BandwidthManager
	NodeAddressing datapath.NodeAddressing
	NodeManager    manager.NodeManager
	DB             *statedb.DB
	Devices        statedb.Table[*tables.Device]
	Orchestrator   datapath.Orchestrator
	ExpConfig      experimental.Config
}

// NewDatapath creates a new Linux datapath
func NewDatapath(p DatapathParams) datapath.Datapath {
	var lbm datapath.LBMap
	if p.ExpConfig.EnableExperimentalLB {
		// The experimental control-plane is enabled. Use a fake LBMap
		// to effectively disable the other code paths writing to LBMaps.
		lbm = mockmaps.NewLBMockMap()
	} else {
		lbm = lbmap.New()
	}

	dp := &linuxDatapath{
		ConfigWriter:    p.ConfigWriter,
		IptablesManager: p.RuleManager,
		nodeAddressing:  p.NodeAddressing,
		lbmap:           lbm,
		bwmgr:           p.BWManager,
		orchestrator:    p.Orchestrator,
	}

	return dp
}

func (l *linuxDatapath) Name() string {
	return "linux-datapath"
}

// LocalNodeAddressing returns the node addressing implementation of the local
// node
func (l *linuxDatapath) LocalNodeAddressing() datapath.NodeAddressing {
	return l.nodeAddressing
}

func (l *linuxDatapath) LBMap() datapath.LBMap {
	return l.lbmap
}

func (l *linuxDatapath) BandwidthManager() datapath.BandwidthManager {
	return l.bwmgr
}

func (l *linuxDatapath) Orchestrator() datapath.Orchestrator {
	return l.orchestrator
}
