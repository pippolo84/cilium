// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriveripam

import (
	"github.com/cilium/hive/cell"
)

// Cell implements the operator side of Multi Pool IPAM for Resources.
var Cell = cell.Module(
	"multi-pool-resource-ipam",
	"Multi Pool DRA Resource IPAM",

	cell.Provide(
		CiliumResourceIPPool,
		NewPoolAllocator,
		NewNodeHandler,
	),
	cell.Invoke(runEventsHandler),
)
