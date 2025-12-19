// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"sort"
	"time"

	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/ipam/types"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/client"
	cilium_client_v2 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/trigger"
)

const (
	multiPoolResourceControllerName = "ipam-sync-resource-multi-pool"
	multiPoolResourceTriggerName    = "ipam-sync-resource-multi-pool-trigger"

	pendingAllocationTTL = 5 * time.Minute

	refreshPoolInterval = time.Minute
)

type ErrPoolNotReadyYet struct {
	poolName Pool
	family   Family
	ip       net.IP
}

func (e *ErrPoolNotReadyYet) Error() string {
	if e.ip == nil {
		return fmt.Sprintf("unable to allocate from pool %q (family %s): pool not (yet) available", e.poolName, e.family)
	} else {
		return fmt.Sprintf("unable to reserve IP %s from pool %q (family %s): pool not (yet) available", e.ip, e.poolName, e.family)
	}
}

func (e *ErrPoolNotReadyYet) Is(err error) bool {
	_, ok := err.(*ErrPoolNotReadyYet)
	return ok
}

var multiPoolResourceControllerGroup = controller.NewGroup(multiPoolResourceControllerName)

type multiPoolManager struct {
	logger *slog.Logger
	conf   *option.DaemonConfig

	mutex             *lock.Mutex
	pendingIPsPerPool *pendingAllocationsPerPool
	pools             map[Pool]*poolPair
	poolsUpdated      chan struct{}
	node              *cilium_v2.CiliumNode
	finishedRestore   map[Family]bool

	controller *controller.Manager
	k8sUpdater *trigger.Trigger
	client     cilium_client_v2.CiliumNodeInterface
}

func newMultiPoolManager(
	logger *slog.Logger,
	conf *option.DaemonConfig,
	cs client.Clientset,
) *multiPoolManager {
	if !cs.IsEnabled() {
		return nil
	}

	k8sController := controller.NewManager()
	k8sUpdater, err := trigger.NewTrigger(trigger.Parameters{
		MinInterval: conf.IPAMCiliumNodeUpdateRate,
		TriggerFunc: func(reasons []string) {
			k8sController.TriggerController(multiPoolResourceControllerName)
		},
		Name: multiPoolResourceTriggerName,
	})
	if err != nil {
		logging.Fatal(logger, "Unable to initialize multi-pool resource CiliumNode synchronization trigger", logfields.Error, err)
		return nil
	}

	return &multiPoolManager{
		logger:            logger,
		conf:              conf,
		mutex:             &lock.Mutex{},
		pendingIPsPerPool: newPendingAllocationsPerPool(logger),
		pools:             map[Pool]*poolPair{},
		poolsUpdated:      make(chan struct{}, 1),
		node:              nil,
		finishedRestore:   map[Family]bool{},
		controller:        k8sController,
		k8sUpdater:        k8sUpdater,
		client:            cs.CiliumV2().CiliumNodes(),
	}
}

func (m *multiPoolManager) ciliumNodeUpdated(newNode *cilium_v2.CiliumNode) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// m.node will only be nil the first time this callback is invoked
	if m.node == nil {
		// This enables the upstream sync controller. It requires m.node to be populated.
		// Note: The controller will only run after m.mutex is unlocked
		m.controller.UpdateController(multiPoolResourceControllerName,
			controller.ControllerParams{
				Group:       multiPoolResourceControllerGroup,
				DoFunc:      m.updateLocalNode,
				RunInterval: refreshPoolInterval,
			})
	}

	for _, pool := range newNode.Spec.IPAM.ResourcePools.Allocated {
		m.upsertPoolLocked(Pool(pool.Pool), pool.CIDRs)
	}

	m.node = newNode
}

func (m *multiPoolManager) updateLocalNode(ctx context.Context) error {
	m.mutex.Lock()

	newNode := m.node.DeepCopy()
	requested := []types.IPAMPoolRequest{}
	allocated := []types.IPAMPoolAllocation{}

	m.pendingIPsPerPool.removeExpiredEntries()
	neededIPsPerPool := m.computeNeededIPsPerPoolLocked()
	for poolName, needed := range neededIPsPerPool {
		if needed.IPv4Addrs == 0 && needed.IPv6Addrs == 0 {
			continue // no need to request "0" IPs
		}

		requested = append(requested, types.IPAMPoolRequest{
			Pool:   poolName.String(),
			Needed: needed,
		})
	}

	// Write in-use pools to podCIDR. This removes any released pod CIDRs
	for poolName, pool := range m.pools {
		neededIPs := neededIPsPerPool[poolName]

		cidrs := []types.IPAMPodCIDR{}
		if v4Pool := pool.v4; v4Pool != nil {
			if m.isRestoreFinishedLocked(IPv4) {
				// releaseExcessCIDRsMultiPool interprets neededIPs as how many
				// free addresses must remain after a CIDR is dropped.
				// Therefore we subtract the number of in-use addresses from neededIPs.
				freeNeeded4 := max(neededIPs.IPv4Addrs-v4Pool.inUseIPCount(), 0)
				v4Pool.releaseExcessCIDRsMultiPool(freeNeeded4)
			}
			v4CIDRs := v4Pool.inUsePodCIDRs()

			slices.Sort(v4CIDRs)
			cidrs = append(cidrs, v4CIDRs...)
		}
		if v6Pool := pool.v6; v6Pool != nil {
			if m.isRestoreFinishedLocked(IPv6) {
				freeNeeded6 := max(neededIPs.IPv6Addrs-v6Pool.inUseIPCount(), 0)
				v6Pool.releaseExcessCIDRsMultiPool(freeNeeded6)
			}
			v6CIDRs := v6Pool.inUsePodCIDRs()

			slices.Sort(v6CIDRs)
			cidrs = append(cidrs, v6CIDRs...)
		}

		// remove pool if we've released all CIDRs
		if len(cidrs) == 0 {
			delete(m.pools, poolName)
			continue
		}

		allocated = append(allocated, types.IPAMPoolAllocation{
			Pool:  poolName.String(),
			CIDRs: cidrs,
		})
	}

	sort.Slice(requested, func(i, j int) bool {
		return requested[i].Pool < requested[j].Pool
	})
	sort.Slice(allocated, func(i, j int) bool {
		return allocated[i].Pool < allocated[j].Pool
	})
	newNode.Spec.IPAM.ResourcePools.Requested = requested
	newNode.Spec.IPAM.ResourcePools.Allocated = allocated

	m.mutex.Unlock()

	if !newNode.Spec.IPAM.ResourcePools.DeepEqual(&m.node.Spec.IPAM.ResourcePools) {
		_, err := m.client.Update(ctx, newNode, meta_v1.UpdateOptions{})
		if err != nil {
			return fmt.Errorf("failed to update node spec: %w", err)
		}
	}

	return nil
}

func (m *multiPoolManager) upsertPoolLocked(poolName Pool, podCIDRs []types.IPAMPodCIDR) {
	pool, ok := m.pools[poolName]
	if !ok {
		pool = &poolPair{}
		if m.conf.IPv4Enabled() {
			pool.v4 = newPodCIDRPool(m.logger)
		}
		if m.conf.IPv6Enabled() {
			pool.v6 = newPodCIDRPool(m.logger)
		}
	}

	var ipv4PodCIDRs, ipv6PodCIDRs []string
	for _, ipamPodCIDR := range podCIDRs {
		podCIDR := string(ipamPodCIDR)
		switch podCIDRFamily(podCIDR) {
		case IPv4:
			ipv4PodCIDRs = append(ipv4PodCIDRs, podCIDR)
		case IPv6:
			ipv6PodCIDRs = append(ipv6PodCIDRs, podCIDR)
		}
	}

	if pool.v4 != nil {
		pool.v4.updatePool(ipv4PodCIDRs)
	}
	if pool.v6 != nil {
		pool.v6.updatePool(ipv6PodCIDRs)
	}

	m.pools[poolName] = pool

	select {
	case m.poolsUpdated <- struct{}{}:
	default:
	}
}

// computeNeededIPsPerPoolLocked computes how many IPs we want to request from
// the operator for each pool. The formula we use for each pool is basically
//
//	neededIPs = roundUp(inUseIPs + pendingIPs + preAllocIPs, preAllocIPs)
//
//	      inUseIPs      Number of IPs that are currently actively in use
//	      pendingIPs    Number of IPs that have been requested, but not yet assigned
//	      preAllocIPs   Minimum number of IPs that we want to pre-allocate as a buffer
//
// Rounded up to the next multiple of preAllocIPs.
func (m *multiPoolManager) computeNeededIPsPerPoolLocked() map[Pool]types.IPAMPoolDemand {
	demand := make(map[Pool]types.IPAMPoolDemand, len(m.pools))

	// inUseIPs
	for poolName, pool := range m.pools {
		ipv4Addrs := 0
		if p := pool.v4; p != nil {
			ipv4Addrs = p.inUseIPCount()
		}
		ipv6Addrs := 0
		if p := pool.v6; p != nil {
			ipv6Addrs = p.inUseIPCount()
		}

		demand[poolName] = types.IPAMPoolDemand{
			IPv4Addrs: ipv4Addrs,
			IPv6Addrs: ipv6Addrs,
		}
	}

	// + pendingIPs
	for poolName, pending := range m.pendingIPsPerPool.pools {
		ipv4Addrs := demand[poolName].IPv4Addrs + pending.pendingForFamily(IPv4)
		ipv6Addrs := demand[poolName].IPv6Addrs + pending.pendingForFamily(IPv6)

		demand[poolName] = types.IPAMPoolDemand{
			IPv4Addrs: ipv4Addrs,
			IPv6Addrs: ipv6Addrs,
		}
	}

	return demand
}

func (m *multiPoolManager) restoreFinished(family Family) {
	m.mutex.Lock()
	m.finishedRestore[family] = true
	m.mutex.Unlock()
}

func (m *multiPoolManager) isRestoreFinishedLocked(family Family) bool {
	return m.finishedRestore[family]
}

func (m *multiPoolManager) poolByFamilyLocked(poolName Pool, family Family) *podCIDRPool {
	switch family {
	case IPv4:
		pair, ok := m.pools[poolName]
		if ok {
			return pair.v4
		}
	case IPv6:
		pair, ok := m.pools[poolName]
		if ok {
			return pair.v6
		}
	}

	return nil
}

func (m *multiPoolManager) allocateNext(owner string, poolName Pool, family Family, syncUpstream bool) (*AllocationResult, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	defer func() {
		m.k8sUpdater.TriggerWithReason("allocation of next IP")
	}()

	pool := m.poolByFamilyLocked(poolName, family)
	if pool == nil {
		m.pendingIPsPerPool.upsertPendingAllocation(poolName, owner, family)
		return nil, &ErrPoolNotReadyYet{poolName: poolName, family: family}
	}

	ip, err := pool.allocateNext()
	if err != nil {
		m.pendingIPsPerPool.upsertPendingAllocation(poolName, owner, family)
		return nil, err
	}

	m.pendingIPsPerPool.markAsAllocated(poolName, owner, family)
	return &AllocationResult{IP: ip, IPPoolName: poolName}, nil
}

func (m *multiPoolManager) releaseIP(ip net.IP, poolName Pool, family Family, upstreamSync bool) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	pool := m.poolByFamilyLocked(poolName, family)
	if pool == nil {
		return fmt.Errorf("unable to release IP %s of unknown pool %q (family %s)", ip, poolName, family)
	}

	pool.release(ip)
	if upstreamSync {
		m.k8sUpdater.TriggerWithReason("release of IP")
	}
	return nil
}

// pendingAllocationsPerPool tracks the number of pending allocations per pool.
// A pending allocation is an allocation that has been requested, but not yet
// fulfilled (i.e. typically because the pool is currently empty).
// If an allocation is pending, we will request one additional IP from the
// operator for every outstanding pending request. We will do this until the
// allocation is fulfilled (e.g. because the operator has replenished our pool),
// or if pending allocation expires (i.e. the owner has not performed any retry
// attempt within pendingAllocationTTL)
type pendingAllocationsPerPool struct {
	logger *slog.Logger
	pools  map[Pool]pendingAllocationsPerOwner
	clock  func() time.Time // support custom clock for testing
}

// newPendingAllocationsPerPool returns a new pendingAllocationsPerPool with the
// default monotonic expiration clock
func newPendingAllocationsPerPool(logger *slog.Logger) *pendingAllocationsPerPool {
	return &pendingAllocationsPerPool{
		logger: logger,
		pools:  map[Pool]pendingAllocationsPerOwner{},
		clock: func() time.Time {
			return time.Now()
		},
	}
}

// upsertPendingAllocation adds (or refreshes) a pending allocation to a particular pool.
// The pending allocation is associated with a particular owner for bookkeeping purposes.
func (p pendingAllocationsPerPool) upsertPendingAllocation(poolName Pool, owner string, family Family) {
	pool, ok := p.pools[poolName]
	if !ok {
		pool = pendingAllocationsPerOwner{}
	}

	p.logger.Debug(
		"IP allocation failed, upserting pending allocation",
		logfields.Owner, owner,
		logfields.Family, family,
		logfields.PoolName, poolName,
	)

	now := p.clock()
	pool.startExpirationAt(now, owner, family)
	p.pools[poolName] = pool
}

// markAsAllocated marks a pending allocation as fulfilled. This means that the owner
// has now been assigned an IP from the given IP family
func (p pendingAllocationsPerPool) markAsAllocated(poolName Pool, owner string, family Family) {
	p.logger.Debug(
		"Marking pending allocation as allocated",
		logfields.Owner, owner,
		logfields.Family, family,
		logfields.PoolName, poolName,
	)

	pool, ok := p.pools[poolName]
	if !ok {
		return
	}
	pool.removeExpiration(owner, family)
	if len(pool) == 0 {
		delete(p.pools, poolName)
	}
}

// removeExpiredEntries removes all expired pending allocations from all pools.
// Pending allocations expire if they are not fulfilled after the time interval
// specified in pendingAllocationTTL has elapsed.
// This typically means that we are no longer trying to reserve an additional IP for
// the expired allocation. The owner of the expired pending allocation may still
// reissue the allocation and be successful next time if the IP pool has now
// enough capacity.
func (p pendingAllocationsPerPool) removeExpiredEntries() {
	now := p.clock()
	for poolName, pool := range p.pools {
		pool.removeExpiredEntries(p.logger, now, poolName)
		if len(pool) == 0 {
			delete(p.pools, poolName)
		}
	}
}

// pendingForPool returns how many IP allocations are pending for the given
// pool and IP family
func (p pendingAllocationsPerPool) pendingForPool(pool Pool, family Family) int {
	return p.pools[pool].pendingForFamily(family)
}

// pendingAllocationsPerOwner tracks if an IP owner has a pending allocation
// request for a particular IP family.
// The IP family as the first key allows one to quickly determine how many
// IP allocations are pending for a given IP family.
type pendingAllocationsPerOwner map[Family]map[string]time.Time

// startExpiration starts the expiration timer for a pending allocation
func (p pendingAllocationsPerOwner) startExpirationAt(now time.Time, owner string, family Family) {
	expires, ok := p[family]
	if !ok {
		expires = map[string]time.Time{}
	}

	expires[owner] = now.Add(pendingAllocationTTL)
	p[family] = expires
}

// removeExpiration removes the expiration timer for a pending allocation, this
// happens either because the timer expired, or the allocation was fulfilled
func (p pendingAllocationsPerOwner) removeExpiration(owner string, family Family) {
	delete(p[family], owner)
	if len(p[family]) == 0 {
		delete(p, family)
	}
}

// removeExpiredEntries removes all pending allocation requests which have expired
func (p pendingAllocationsPerOwner) removeExpiredEntries(logger *slog.Logger, now time.Time, pool Pool) {
	for family, owners := range p {
		for owner, expires := range owners {
			if now.After(expires) {
				p.removeExpiration(owner, family)
				logger.Debug(
					"Pending IP allocation has expired without being fulfilled",
					logfields.Owner, owner,
					logfields.Family, family,
					logfields.PoolName, pool,
				)
			}
		}
	}
}

// pendingForPool returns how many IP allocations are pending for the given family
func (p pendingAllocationsPerOwner) pendingForFamily(family Family) int {
	return len(p[family])
}

// neededIPCeil rounds up numIPs to the next but one multiple of preAlloc.
// Example for preAlloc=16:
//
//	numIP  0 -> 16
//	numIP  1 -> 32
//	numIP 15 -> 32
//	numIP 16 -> 32
//	numIP 17 -> 48
//
// This always ensures that there we always have a buffer of at least preAlloc
// IPs.
func neededIPCeil(numIP int, preAlloc int) int {
	if preAlloc == 0 {
		return numIP
	}

	quotient := numIP / preAlloc
	rem := numIP % preAlloc
	if rem > 0 {
		return (quotient + 2) * preAlloc
	}
	return (quotient + 1) * preAlloc
}
