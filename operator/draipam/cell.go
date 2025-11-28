// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package draipam

import (
	"github.com/cilium/hive/cell"
)

// Cell implements a network driver to manage DRA resources.
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
