// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dra

import (
	"context"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	"github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/option"
)

func runEventsHandler(
	jg job.Group,
	localNode k8s.LocalCiliumNodeResource,
	daemonCfg *option.DaemonConfig,
	mgr *multiPoolManager,
) {
	jg.Add(
		job.OneShot(
			"dra-ipam-node-handler",
			func(ctx context.Context, health cell.Health) error {
				for ev := range localNode.Events(ctx) {
					switch ev.Kind {
					case resource.Sync:
						if daemonCfg.EnableIPv4 {
							mgr.restoreFinished(IPv4)
						}
						if daemonCfg.EnableIPv6 {
							mgr.restoreFinished(IPv6)
						}
					case resource.Upsert:
						mgr.ciliumNodeUpdated(ev.Object)
					}
					ev.Done(nil)
				}
				return nil
			},
		),
	)
}
