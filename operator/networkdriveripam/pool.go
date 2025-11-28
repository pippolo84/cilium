// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriveripam

import (
	"errors"
	"fmt"
	"math/big"
	"net/netip"
	"slices"

	"go4.org/netipx"

	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/ipam/allocator/clusterpool/cidralloc"
	"github.com/cilium/cilium/pkg/ipam/types"
)

var errPoolEmpty = errors.New("pool empty")

type cidrPool struct {
	v4         []cidralloc.CIDRAllocator
	v6         []cidralloc.CIDRAllocator
	v4MaskSize int
	v6MaskSize int
}

type cidrSet map[netip.Prefix]struct{}

func (c cidrSet) PodCIDRSlice() []types.IPAMPodCIDR {
	cidrs := make([]types.IPAMPodCIDR, 0, len(c))
	for cidr := range c {
		cidrs = append(cidrs, types.IPAMPodCIDR(cidr.String()))
	}
	slices.Sort(cidrs)
	return cidrs
}

// availableAddrs returns the number of available addresses in this set
func (c cidrSet) availableAddrs() *big.Int {
	total := big.NewInt(0)
	for p := range c {
		total.Add(total, addrsInPrefix(p))
	}
	return total
}

type cidrSets struct {
	v4 cidrSet
	v6 cidrSet
}

func (c *cidrPool) allocCIDR(family ipam.Family) (netip.Prefix, error) {
	switch family {
	case ipam.IPv4:
		return allocFirstFreeCIDR(c.v4)
	case ipam.IPv6:
		return allocFirstFreeCIDR(c.v6)
	default:
		return netip.Prefix{}, fmt.Errorf("invalid cidr family: %s", family)
	}
}

func (c *cidrPool) occupyCIDR(cidr netip.Prefix) error {
	if cidr.Addr().Is4() {
		return occupyCIDR(c.v4, cidr)
	} else {
		return occupyCIDR(c.v6, cidr)
	}
}

func (c *cidrPool) releaseCIDR(cidr netip.Prefix) error {
	if cidr.Addr().Is4() {
		return releaseCIDR(c.v4, cidr)
	} else {
		return releaseCIDR(c.v6, cidr)
	}
}

func (c *cidrPool) hasCIDR(cidr netip.Prefix) bool {
	if cidr.Addr().Is4() {
		return hasCIDR(c.v4, cidr)
	} else {
		return hasCIDR(c.v6, cidr)
	}
}

func allocFirstFreeCIDR(allocators []cidralloc.CIDRAllocator) (netip.Prefix, error) {
	for _, alloc := range allocators {
		if alloc.IsFull() {
			continue
		}

		ipnet, err := alloc.AllocateNext()
		if err != nil {
			return netip.Prefix{}, err
		}

		prefix, ok := netipx.FromStdIPNet(ipnet)
		if !ok {
			return netip.Prefix{}, fmt.Errorf("invalid cidr %s allocated", ipnet)
		}
		return prefix, nil
	}

	return netip.Prefix{}, errPoolEmpty
}

func occupyCIDR(allocators []cidralloc.CIDRAllocator, cidr netip.Prefix) error {
	ipnet := netipx.PrefixIPNet(cidr)
	for _, alloc := range allocators {
		if !alloc.InRange(ipnet) {
			continue
		}
		if alloc.IsFull() {
			return errPoolEmpty
		}
		allocated, err := alloc.IsAllocated(ipnet)
		if err != nil {
			return err
		}
		if allocated {
			return fmt.Errorf("cidr %s has already been allocated", cidr)
		}

		return alloc.Occupy(ipnet)
	}

	return fmt.Errorf("cidr %s is not part of the requested pool", cidr)
}

func releaseCIDR(allocators []cidralloc.CIDRAllocator, cidr netip.Prefix) error {
	ipnet := netipx.PrefixIPNet(cidr)
	for _, alloc := range allocators {
		if !alloc.InRange(ipnet) {
			continue
		}

		allocated, err := alloc.IsAllocated(ipnet)
		if err != nil {
			return err
		}
		if !allocated {
			return nil // not an error to release a cidr twice
		}

		return alloc.Release(ipnet)
	}

	return fmt.Errorf("released cidr %s was not part the pool", cidr)
}

func hasCIDR(allocators []cidralloc.CIDRAllocator, cidr netip.Prefix) bool {
	for _, alloc := range allocators {
		if alloc.IsClusterCIDR(cidr) {
			return true
		}
	}
	return false
}

func containsCIDR(allocators []cidralloc.CIDRAllocator, cidr netip.Prefix) bool {
	ipnet := netipx.PrefixIPNet(cidr)
	for _, alloc := range allocators {
		if alloc.InRange(ipnet) {
			return true
		}
	}
	return false
}

// addrsInPrefix calculates the number of usable addresses in a prefix p, or 0 if p is not valid.
func addrsInPrefix(p netip.Prefix) *big.Int {
	if !p.IsValid() {
		return big.NewInt(0)
	}

	// compute number of addresses in prefix, i.e. 2^bits
	addrs := new(big.Int)
	addrs.Lsh(big.NewInt(1), uint(p.Addr().BitLen()-p.Bits()))

	// prefix has less than 3 addresses
	two := big.NewInt(2)
	if addrs.Cmp(two) <= 0 {
		return addrs
	}

	// subtract network and broadcast address, which are not available for
	// allocation in the cilium/ipam library for now
	addrs.Sub(addrs, two)
	if addrs.Sign() < 0 {
		return big.NewInt(0)
	}

	return addrs
}
