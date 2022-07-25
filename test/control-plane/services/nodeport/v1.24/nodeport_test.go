// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v1_24

import (
	"testing"

	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/test/control-plane/services"

	operatorOption "github.com/cilium/cilium/operator/option"
)

func TestNodePort(t *testing.T) {
	modConfig := func(daemonCfg *option.DaemonConfig, operatorCfg *operatorOption.OperatorConfig) {
		daemonCfg.EnableNodePort = true
	}
	services.NewGoldenServicesTest(t, "nodeport-control-plane").Run(t, "1.24", modConfig)
}
