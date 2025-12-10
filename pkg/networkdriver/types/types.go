// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"encoding/json"
	"errors"
	"net/netip"
	"strings"

	resourceapi "k8s.io/api/resource/v1"
)

var (
	errUnknownDriverType = errors.New("unknown driver type")
)

type DeviceManagerType int

const (
	sriovDeviceManagerStr = "sr-iov"
	dummyDeviceManagerStr = "dummy"
)

const (
	DeviceManagerTypeSRIOV DeviceManagerType = iota
	DeviceManagerTypeDummy

	DeviceManagerTypeUnknown
)

func (d DeviceManagerType) String() string {
	switch d {
	case DeviceManagerTypeSRIOV:
		return sriovDeviceManagerStr
	case DeviceManagerTypeDummy:
		return dummyDeviceManagerStr
	}

	return ""
}

func (d DeviceManagerType) MarshalText() (text []byte, err error) {
	switch d {
	case DeviceManagerTypeSRIOV:
		return json.Marshal(sriovDeviceManagerStr)
	case DeviceManagerTypeDummy:
		return json.Marshal(dummyDeviceManagerStr)
	}

	return nil, errUnknownDriverType
}

func (d *DeviceManagerType) UnmarshalText(text []byte) error {
	var s string
	err := json.Unmarshal(text, &s)
	if err != nil {
		return err
	}

	switch strings.ToLower(s) {
	case sriovDeviceManagerStr:
		*d = DeviceManagerTypeSRIOV
	case dummyDeviceManagerStr:
		*d = DeviceManagerTypeDummy
	default:
		return errUnknownDriverType
	}

	return nil
}

type Device interface {
	GetAttrs() map[resourceapi.QualifiedName]resourceapi.DeviceAttribute
	Setup(cfg DeviceConfig) error
	Free(cfg DeviceConfig) error
	Match(filter DeviceFilter) bool
	IfName() string
	KernelIfName() string
}

type DeviceManager interface {
	ListDevices() ([]Device, error)
}

type DeviceManagerConfig interface {
	IsEnabled() bool
}

type DeviceFilter struct {
	PfNames     []string
	PciAddrs    []string
	Drivers     []string
	DeviceIDs   []string
	VendorIDs   []string
	IfNames     []string
	DriverTypes []DeviceManagerType
}

type RouteSet map[netip.Prefix]AddrSet

type AddrSet map[netip.Prefix]struct{}

// DeviceClaimConfig is the device configuration set in the ResourceClaim Status.
type DeviceClaimConfig struct {
	IPPool string `json:"ip-pool"`
	Routes RouteSet
	Vlan   uint16
}

func (d *DeviceClaimConfig) Empty() bool {
	return d.IPPool == "" &&
		d.Routes == nil &&
		d.Vlan == 0
}

// DeviceAllocationConfig is the additional device configuration resulting from
// processing the DeviceClaimConfig in the PrepareResourceClaims.
type DeviceAllocationConfig struct {
	IPv4 netip.Addr
	IPv6 netip.Addr
}

// DeviceConfig is the complete device configuration that is set in the NRI plugin.
type DeviceConfig struct {
	DeviceClaimConfig
	DeviceAllocationConfig
}
