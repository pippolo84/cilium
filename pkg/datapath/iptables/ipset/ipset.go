// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipset

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"runtime/pprof"
	"strings"

	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/statedb/reconciler"
)

const (
	CiliumNodeIPSetV4 = "cilium_node_set_v4"
	CiliumNodeIPSetV6 = "cilium_node_set_v6"
)

type Family string

const (
	INetFamily  Family = "inet"
	INet6Family Family = "inet6"
)

type AddrSet = sets.Set[netip.Addr]

// Manager handles the kernel IP sets configuration
type Manager interface {
	AddToIPSet(name string, family Family, addrs ...netip.Addr)
	RemoveFromIPSet(name string, addrs ...netip.Addr)
}

type manager struct {
	logger  logrus.FieldLogger
	enabled bool

	db    *statedb.DB
	table statedb.RWTable[*tables.IPSetEntry]

	ipset *ipset
}

// AddToIPSet adds the addresses to the ipset with given name and family.
// It creates the ipset if it doesn't already exist and doesn't error out
// if either the ipset or the IP already exist.
func (m *manager) AddToIPSet(name string, family Family, addrs ...netip.Addr) {
	if !m.enabled {
		return
	}

	txn := m.db.WriteTxn(m.table)
	defer txn.Abort()

	for _, addr := range addrs {
		key := tables.IPSetEntryKey{
			Name: name,
			Addr: addr,
		}
		if _, _, found := m.table.First(txn, tables.IPSetEntryIndex.Query(key)); found {
			continue
		}
		_, _, _ = m.table.Insert(txn, &tables.IPSetEntry{
			Name:   name,
			Family: string(family),
			Addr:   addr,
			Status: reconciler.StatusPending(),
		})
	}

	txn.Commit()
}

// RemoveFromIPSet removes the addresses from the specified ipset.
func (m *manager) RemoveFromIPSet(name string, addrs ...netip.Addr) {
	if !m.enabled {
		return
	}

	txn := m.db.WriteTxn(m.table)
	defer txn.Abort()

	for _, addr := range addrs {
		key := tables.IPSetEntryKey{
			Name: name,
			Addr: addr,
		}
		obj, _, found := m.table.First(txn, tables.IPSetEntryIndex.Query(key))
		if !found {
			continue
		}
		m.table.Insert(txn, obj.WithStatus(reconciler.StatusPendingDelete()))
	}

	txn.Commit()
}

func newIPSetManager(
	logger logrus.FieldLogger,
	lc cell.Lifecycle,
	jobRegistry job.Registry,
	scope cell.Scope,
	db *statedb.DB,
	table statedb.RWTable[*tables.IPSetEntry],
	cfg config,
	ipset *ipset,
	_ reconciler.Reconciler[*tables.IPSetEntry], // needed to enforce the correct hive ordering
) Manager {
	db.RegisterTable(table)
	mgr := &manager{
		logger:  logger,
		enabled: cfg.NodeIPSetNeeded,
		db:      db,
		table:   table,
		ipset:   ipset,
	}

	lc.Append(cell.Hook{
		OnStart: func(ctx cell.HookContext) error {
			if !cfg.NodeIPSetNeeded {
				return nil
			}

			// When NodeIPSetNeeded is set, node ipsets must be created even if empty,
			// to avoid failures when referencing them in iptables masquerading rules.
			if err := ipset.create(ctx, CiliumNodeIPSetV4, string(INetFamily)); err != nil {
				return fmt.Errorf("error while creating ipset %s", CiliumNodeIPSetV4)
			}
			if err := ipset.create(ctx, CiliumNodeIPSetV6, string(INet6Family)); err != nil {
				return fmt.Errorf("error while creating ipset %s", CiliumNodeIPSetV6)
			}
			return nil
		},
	})

	jg := jobRegistry.NewGroup(
		scope,
		job.WithLogger(logger),
		job.WithPprofLabels(pprof.Labels("cell", "ipset")),
	)
	jg.Add(job.OneShot("ipset-init-finalizer", mgr.init))
	lc.Append(jg)

	return mgr
}

func (m *manager) init(ctx context.Context, _ cell.HealthReporter) error {
	if !m.enabled {
		// If node ipsets are not needed, clear the Cilium managed ones to remove possible stale entries.
		for _, ciliumNodeIPSet := range []string{CiliumNodeIPSetV4, CiliumNodeIPSetV6} {
			if err := m.ipset.remove(ctx, ciliumNodeIPSet); err != nil {
				m.logger.WithError(err).Infof("Unable to remove stale ipset %s. This is usually due to a stale iptables rule referring to it. "+
					"The set will not be removed. This is harmless and it will be removed at the next Cilium restart, when the stale iptables rule has been removed.", ciliumNodeIPSet)
			}
		}
		return nil
	}

	return nil
}

type ipset struct {
	executable

	log logrus.FieldLogger
}

func (i *ipset) create(ctx context.Context, name string, family string) error {
	if _, err := i.run(ctx, "create", name, "iphash", "family", family, "-exist"); err != nil {
		return fmt.Errorf("failed to create ipset %s: %w", name, err)
	}
	return nil
}

func (i *ipset) remove(ctx context.Context, name string) error {
	if _, err := i.run(ctx, "list", name); err != nil {
		// ipset does not exist, nothing to remove
		return nil
	}
	if _, err := i.run(ctx, "destroy", name); err != nil {
		return fmt.Errorf("failed to remove ipset %s: %w", name, err)
	}
	return nil
}

func (i *ipset) list(ctx context.Context, name string) (AddrSet, error) {
	out, err := i.run(ctx, "list", name)
	if err != nil {
		return AddrSet{}, fmt.Errorf("failed to list ipset %s: %w", name, err)
	}

	addrs := AddrSet{}
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		addr, err := netip.ParseAddr(line)
		if err != nil {
			continue
		}
		addrs = addrs.Insert(addr)
	}
	if err := scanner.Err(); err != nil {
		return AddrSet{}, fmt.Errorf("failed to scan ipset %s: %w", name, err)
	}
	return addrs, nil
}

func (i *ipset) add(ctx context.Context, name string, addr netip.Addr) error {
	if _, err := i.run(ctx, "add", name, addr.String(), "-exist"); err != nil {
		return fmt.Errorf("failed to add %s to ipset %s: %w", addr, name, err)
	}
	return nil
}

func (i *ipset) del(ctx context.Context, name string, addr netip.Addr) error {
	if _, err := i.run(ctx, "del", name, addr.String(), "-exist"); err != nil {
		return fmt.Errorf("failed to del %s to ipset %s: %w", addr, name, err)
	}
	return nil
}

func (i *ipset) run(ctx context.Context, args ...string) ([]byte, error) {
	i.log.Debugf("Running command %s", i.fullCommand(args...))
	return i.exec(ctx, "ipset", args...)
}

func (i *ipset) fullCommand(args ...string) string {
	return strings.Join(append([]string{"ipset"}, args...), " ")
}

// useful to ease the creation of a mock ipset command for testing purposes
type executable interface {
	exec(ctx context.Context, name string, arg ...string) ([]byte, error)
}

type funcExecutable func(ctx context.Context, name string, arg ...string) ([]byte, error)

func (f funcExecutable) exec(ctx context.Context, name string, arg ...string) ([]byte, error) {
	return f(ctx, name, arg...)
}
