// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package controlplane

import (
	"context"

	"github.com/cilium/cilium/operator/cmd"
)

func startCiliumOperator() {
	cmd.OnOperatorStartLeading(context.Background())
}
