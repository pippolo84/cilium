// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriveripam

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"k8s.io/client-go/util/workqueue"

	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

func CiliumResourceIPPool(
	lc cell.Lifecycle,
	cs client.Clientset,
	mp workqueue.MetricsProvider,
) (resource.Resource[*cilium_v2alpha1.CiliumResourceIPPool], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherWithModifiers(utils.ListerWatcherFromTyped(cs.CiliumV2alpha1().CiliumResourceIPPools()))
	return resource.New[*cilium_v2alpha1.CiliumResourceIPPool](lc, lw, mp, resource.WithMetric("CiliumResourceIPPool")), nil
}

func runEventsHandler(
	logger *slog.Logger,
	lc cell.Lifecycle,
	jg job.Group,
	ipPools resource.Resource[*cilium_v2alpha1.CiliumResourceIPPool],
	ciliumNodes resource.Resource[*cilium_v2.CiliumNode],
	allocator *PoolAllocator,
	nodeHandler *NodeHandler,
) {

	poolSynced, nodeSynced := make(chan struct{}), make(chan struct{})

	jg.Add(
		job.OneShot(
			"dra-ipam-pool-handler",
			func(ctx context.Context, health cell.Health) error {
				for ev := range ipPools.Events(ctx) {
					var err error
					var action string

					switch ev.Kind {
					case resource.Sync:
						logger.InfoContext(ctx, "All CiliumResourceIPPool resources synchronized")
						close(poolSynced)
					case resource.Upsert:
						err = allocator.upsertPool(ctx, ev.Object)
						action = "upsert"
					case resource.Delete:
						err = allocator.deletePool(ctx, ev.Object)
						action = "delete"
					}
					ev.Done(err)
					if err != nil {
						logger.ErrorContext(ctx, fmt.Sprintf("failed to %s pool %q", action, ev.Key), logfields.Error, err)
					}
				}

				return nil
			},
		),
		job.OneShot(
			"dra-ipam-node-handler",
			func(ctx context.Context, health cell.Health) error {
				for ev := range ciliumNodes.Events(ctx) {
					switch ev.Kind {
					case resource.Sync:
						logger.InfoContext(ctx, "All CiliumNode resources synchronized")
						close(nodeSynced)
					case resource.Upsert:
						nodeHandler.Upsert(ev.Object)
					case resource.Delete:
						nodeHandler.Delete(ev.Object)
					}
					ev.Done(nil)
				}
				return nil
			},
		),
		job.OneShot(
			"dra-ipam-initial-resync",
			func(ctx context.Context, health cell.Health) error {
				<-poolSynced
				<-nodeSynced
				nodeHandler.Resync(ctx, time.Time{})
				return nil
			},
		),
	)

	lc.Append(cell.Hook{
		OnStop: func(_ cell.HookContext) error {
			nodeHandler.controllerManager.RemoveAllAndWait()
			return nil
		},
	})
}
