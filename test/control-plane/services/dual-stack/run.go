// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dualstack

import (
	"testing"

	fakeDatapath "github.com/cilium/cilium/pkg/datapath/fake"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/option"
	controlplane "github.com/cilium/cilium/test/control-plane"
	. "github.com/cilium/cilium/test/control-plane/services"

	operatorOption "github.com/cilium/cilium/operator/option"
)

func RunDualStackTestWithVersion(t *testing.T, version string) {
	testCase := NewGoldenServicesTest(t, "dual-stack-worker")

	testCase.Steps[0].AddValidationFunc(func(datapath *fakeDatapath.FakeDatapath, proxy *controlplane.K8sObjsProxy) error {
		assert := NewLBMapAssert(datapath.LBMockMap())

		// Verify that default/echo-dualstack service exists
		// for both NodePort and ClusterIP, and that it has backends
		// for udp:69, and tcp:80 for both IPv4 and IPv6.
		err := assert.ServicesExist(
			"default/echo-dualstack",
			[]lb.SVCType{lb.SVCTypeNodePort, lb.SVCTypeClusterIP},
			[]SVCL3Type{SVCIPv4, SVCIPv6},
			lb.UDP,
			69)
		if err != nil {
			return err
		}

		err = assert.ServicesExist(
			"default/echo-dualstack",
			[]lb.SVCType{lb.SVCTypeNodePort, lb.SVCTypeClusterIP},
			[]SVCL3Type{SVCIPv4, SVCIPv6},
			lb.TCP,
			80)
		if err != nil {
			return err
		}

		return nil
	})

	modConfig := func(daemonCfg *option.DaemonConfig, operatorCfg *operatorOption.OperatorConfig) {
		daemonCfg.EnableIPv6 = true
		daemonCfg.EnableNodePort = true
	}
	testCase.Run(t, version, modConfig)
}
