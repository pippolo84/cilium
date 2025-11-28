// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriveripam

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/ipam/allocator"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/client"
	cilium_client_v2 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

type NodeHandler struct {
	logger *slog.Logger
	mutex  lock.Mutex

	poolAllocator *PoolAllocator
	client        cilium_client_v2.CiliumNodeInterface

	nodesPendingAllocation map[string]*cilium_v2.CiliumNode
	restoreFinished        bool

	controllerManager                *controller.Manager
	controllerErrorRetryBaseDuration time.Duration // only set in unit tests

	synced chan struct{}
}

var ipamMultipoolSyncControllerGroup = controller.NewGroup("ipam-resource-multi-pool-sync")

var _ allocator.NodeEventHandler = (*NodeHandler)(nil)

func NewNodeHandler(logger *slog.Logger, cs client.Clientset, poolAllocator *PoolAllocator) *NodeHandler {
	if !cs.IsEnabled() {
		return nil
	}

	return &NodeHandler{
		logger:                 logger,
		poolAllocator:          poolAllocator,
		client:                 cs.CiliumV2().CiliumNodes(),
		nodesPendingAllocation: map[string]*cilium_v2.CiliumNode{},
		controllerManager:      controller.NewManager(),
		synced:                 make(chan struct{}),
	}
}

func (n *NodeHandler) Upsert(resource *cilium_v2.CiliumNode) {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	n.upsertLocked(resource)
}

func (n *NodeHandler) Delete(resource *cilium_v2.CiliumNode) {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	err := n.poolAllocator.ReleaseNode(resource.Name)
	if err != nil {
		n.logger.Warn(
			"Errors while release node and its CIDRs",
			logfields.Error, err,
			logfields.NodeName, resource.Name,
		)
	}

	delete(n.nodesPendingAllocation, resource.Name)

	// Make sure any pending update controller is stopped
	n.controllerManager.RemoveController(controllerName(resource.Name))
}

func (n *NodeHandler) Resync(context.Context, time.Time) {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	n.poolAllocator.RestoreFinished()
	for _, cn := range n.nodesPendingAllocation {
		delete(n.nodesPendingAllocation, cn.Name)
		n.createUpsertController(cn)
	}
	n.restoreFinished = true
	n.nodesPendingAllocation = nil
}

func (n *NodeHandler) upsertLocked(resource *cilium_v2.CiliumNode) {
	if !n.restoreFinished {
		n.nodesPendingAllocation[resource.Name] = resource
		_ = n.poolAllocator.AllocateToNode(resource)
		return
	}

	n.createUpsertController(resource)
}

func (n *NodeHandler) createUpsertController(resource *cilium_v2.CiliumNode) {
	// This controller serves two purposes:
	// 1. It will retry allocations upon failure, e.g. if a pool does not exist yet.
	// 2. Will try to synchronize the allocator's state with the CiliumNode CRD in k8s.
	refetchNode := false
	n.controllerManager.UpdateController(controllerName(resource.Name), controller.ControllerParams{
		Group:                  ipamMultipoolSyncControllerGroup,
		ErrorRetryBaseDuration: n.controllerErrorRetryBaseDuration,
		DoFunc: func(ctx context.Context) error {
			// errorMessage is written to the resource status
			errorMessage := ""
			var controllerErr error

			// If a previous run of the controller failed due to a conflict,
			// we need to re-fetch the node to make sure we have the latest version.
			if refetchNode {
				resource, controllerErr = n.client.Get(context.TODO(), resource.Name, meta_v1.GetOptions{})
				if controllerErr != nil {
					return controllerErr
				}
				refetchNode = false
			}

			err := n.poolAllocator.AllocateToNode(resource)
			if err != nil {
				n.logger.Warn(
					"Failed to allocate PodCIDRs to node",
					logfields.Error, err,
					logfields.NodeName, resource.Name,
				)
				errorMessage = err.Error()
				controllerErr = err
			}

			newResource := resource.DeepCopy()
			newResource.Status.IPAM.OperatorStatus.Error = errorMessage

			newResource.Spec.IPAM.ResourcePools.Allocated = n.poolAllocator.AllocatedPools(newResource.Name)

			if !newResource.Spec.IPAM.ResourcePools.DeepEqual(&resource.Spec.IPAM.ResourcePools) {
				_, err = updateCiliumNode(context.TODO(), n.client, resource, newResource)
				if err != nil {
					controllerErr = errors.Join(controllerErr, fmt.Errorf("failed to update spec: %w", err))
					if k8sErrors.IsConflict(err) {
						refetchNode = true
					}
				}
			}

			if !newResource.Status.IPAM.OperatorStatus.DeepEqual(&resource.Status.IPAM.OperatorStatus) && !refetchNode {
				_, err = updateCiliumNodeStatus(context.TODO(), n.client, resource, newResource)
				if err != nil {
					controllerErr = errors.Join(controllerErr, fmt.Errorf("failed to update status: %w", err))
					if k8sErrors.IsConflict(err) {
						refetchNode = true
					}
				}
			}

			return controllerErr
		},
	})
}

func controllerName(nodeName string) string {
	return "ipam-multi-pool-sync-" + nodeName
}

func updateCiliumNodeStatus(ctx context.Context, client cilium_client_v2.CiliumNodeInterface, origNode, node *cilium_v2.CiliumNode) (*cilium_v2.CiliumNode, error) {
	if origNode == nil || !origNode.Status.DeepEqual(&node.Status) {
		return client.UpdateStatus(ctx, node, meta_v1.UpdateOptions{})
	}
	return nil, nil
}

func updateCiliumNode(ctx context.Context, client cilium_client_v2.CiliumNodeInterface, origNode, node *cilium_v2.CiliumNode) (*cilium_v2.CiliumNode, error) {
	if origNode == nil || !origNode.Spec.DeepEqual(&node.Spec) {
		return client.Update(ctx, node, meta_v1.UpdateOptions{})
	}
	return nil, nil
}
