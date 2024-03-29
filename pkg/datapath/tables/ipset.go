// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tables

import (
	"net/netip"

	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/statedb/index"
	"github.com/cilium/cilium/pkg/statedb/reconciler"
)

const IPSetsTableName = "ipsets"

type IPSetEntryKey struct {
	Name string
	Addr netip.Addr
}

func (k IPSetEntryKey) Key() index.Key {
	return append(index.NetIPAddr(k.Addr), []byte(k.Name)...)
}

var IPSetEntryIndex = statedb.Index[*IPSetEntry, IPSetEntryKey]{
	Name: IPSetsTableName,
	FromObject: func(s *IPSetEntry) index.KeySet {
		return index.NewKeySet(IPSetEntryKey{s.Name, s.Addr}.Key())
	},
	FromKey: IPSetEntryKey.Key,
	Unique:  true,
}

func NewIPSetTable(db *statedb.DB) (statedb.RWTable[*IPSetEntry], error) {
	tbl, err := statedb.NewTable(
		IPSetsTableName,
		IPSetEntryIndex,
	)
	return tbl, err
}

func (s *IPSetEntry) TableHeader() []string {
	return []string{"Name", "Family", "Addr", "Status"}
}

func (s *IPSetEntry) TableRow() []string {
	return []string{s.Name, s.Family, s.Addr.String(), s.Status.String()}
}

type IPSetEntry struct {
	Name   string
	Family string
	Addr   netip.Addr

	Status reconciler.Status
}

func (s *IPSetEntry) GetStatus() reconciler.Status {
	return s.Status
}

func (s *IPSetEntry) WithStatus(newStatus reconciler.Status) *IPSetEntry {
	return &IPSetEntry{
		Name:   s.Name,
		Family: s.Family,
		Addr:   s.Addr,
		Status: newStatus,
	}
}
