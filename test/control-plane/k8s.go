package controlplane

import (
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/version"
	"github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/proxy"

	operatorOption "github.com/cilium/cilium/operator/option"
	fqdnproxy "github.com/cilium/cilium/pkg/fqdn/proxy"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
)

func configureEnvironment(nodeName string, clients fakeClients, modConfig func(*option.DaemonConfig, *operatorOption.OperatorConfig)) {
	types.SetName(nodeName)

	// Configure k8s and perform capability detection with the fake client.
	k8s.Configure("dummy", "dummy", 10.0, 10)
	version.Update(clients.core, &k8sConfig{})
	k8s.SetClients(clients.core, clients.slim, clients.cilium, clients.apiext)

	proxy.DefaultDNSProxy = fqdnproxy.MockFQDNProxy{}

	option.Config.Populate()
	option.Config.IdentityAllocationMode = option.IdentityAllocationModeCRD
	option.Config.DryMode = true
	option.Config.IPAM = ipamOption.IPAMKubernetes
	option.Config.Opts = option.NewIntOptions(&option.DaemonMutableOptionLibrary)
	option.Config.Opts.SetBool(option.DropNotify, true)
	option.Config.Opts.SetBool(option.TraceNotify, true)
	option.Config.Opts.SetBool(option.PolicyVerdictNotify, true)
	option.Config.Opts.SetBool(option.Debug, true)
	option.Config.EnableIPSec = false
	option.Config.EnableIPv6 = false
	option.Config.KubeProxyReplacement = option.KubeProxyReplacementStrict
	option.Config.EnableHostIPRestore = false
	option.Config.K8sRequireIPv6PodCIDR = false
	option.Config.K8sEnableK8sEndpointSlice = true
	option.Config.EnableL7Proxy = false
	option.Config.EnableHealthCheckNodePort = false
	option.Config.Debug = true

	operatorOption.Config.Populate()

	// Apply the test specific configuration
	modConfig(option.Config, operatorOption.Config)
}
