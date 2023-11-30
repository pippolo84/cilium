// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bgpv2

import (
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/hive/cell"
)

const (
	// BGPv2Enabled is the name of the flag that enables BGPv2 APIs in Cilium.
	BGPv2Enabled = "enable-bgp-v2-api"
)

var Cell = cell.Module(
	"bgp-cp-operator",
	"BGP Control Plane Operator",
	cell.Config(Config{}),
	cell.Invoke(registerBGPResourceManager),
)

type Config struct {
	BGPv2Enabled bool `mapstructure:"enable-bgp-v2-api"`
}

// Flags implements cell.Flagger interface.
func (cfg Config) Flags(flags *pflag.FlagSet) {
	flags.Bool(BGPv2Enabled, cfg.BGPv2Enabled, "Enables BGPv2 APIs in Cilium")
}
