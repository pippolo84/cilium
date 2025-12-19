// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"path"

	"go4.org/netipx"
	resourceapi "k8s.io/api/resource/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kube_types "k8s.io/apimachinery/pkg/types"
	"k8s.io/dynamic-resource-allocation/kubeletplugin"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/networkdriver/types"
	"github.com/cilium/cilium/pkg/resiliency"
	"github.com/cilium/cilium/pkg/time"
)

const (
	ipamRetryInterval = 2500 * time.Millisecond
	ipamMaxRetries    = 120
)

// HandleError logs out error messages from kubelet.
func (d *Driver) HandleError(ctx context.Context, err error, msg string) {
	d.logger.ErrorContext(
		ctx, "HandleError called:",
		logfields.Error, err,
		logfields.Message, msg,
	)
}

func (driver *Driver) releaseAddrs(cfg types.DeviceConfig) error {
	var errs []error
	if driver.ipv4Enabled {
		if err := driver.ipam.releaseIP(cfg.IPv4Addr.Addr().AsSlice(), Pool(cfg.IPPool), IPv4, true); err != nil {
			errs = append(errs, fmt.Errorf("failed to release IP address: %w", err))
		}
	}
	if driver.ipv6Enabled {
		if err := driver.ipam.releaseIP(cfg.IPv4Addr.Addr().AsSlice(), Pool(cfg.IPPool), IPv6, true); err != nil {
			errs = append(errs, fmt.Errorf("failed to release IP address: %w", err))
		}
	}
	return errors.Join(errs...)
}

// unprepareResourceClaim removes an allocation and frees up the device.
func (d *Driver) unprepareResourceClaim(ctx context.Context, claim kubeletplugin.NamespacedObject) error {
	var errs []error
	var found bool

	for pod, alloc := range d.allocations {
		devices, ok := alloc[claim.UID]
		if ok {
			found = true
			for _, dev := range devices {
				if err := d.releaseAddrs(dev.Config); err != nil {
					errs = append(errs, err)
				}
				if err := dev.Device.Free(dev.Config); err != nil {
					errs = append(errs, err)
				}
			}
		}

		if found {
			delete(alloc, claim.UID)
			// see if pod ended up without any allocations.
			// clean it up if we just removed the last one.
			if len(alloc) == 0 {
				delete(d.allocations, pod)
			}

			break
		}
	}

	if !found {
		d.logger.DebugContext(
			ctx, "no allocation found for claim",
			logfields.UID, claim.UID,
			logfields.K8sNamespace, claim.Namespace,
			logfields.Name, claim.Name,
		)
	}

	return errors.Join(errs...)
}

// UnprepareResourceClaims gets called whenever we have a request to deallocate a resource claim. ex: pod goes away.
func (driver *Driver) UnprepareResourceClaims(ctx context.Context, claims []kubeletplugin.NamespacedObject) (result map[kube_types.UID]error, err error) {
	driver.logger.DebugContext(ctx, fmt.Sprintf("UnprepareResourceClaims called with %d claims", len(claims)))

	result = make(map[kube_types.UID]error, len(claims))

	err = driver.withLock(func() error {
		for _, c := range claims {
			result[c.UID] = driver.unprepareResourceClaim(ctx, c)
			driver.logger.DebugContext(
				ctx, "freeing resources for claim",
				logfields.Name, c.Name,
				logfields.K8sNamespace, c.Namespace,
				logfields.UID, string(c.UID),
				logfields.Error, result[c.UID],
			)
		}

		return nil
	})

	return result, err
}

func (driver *Driver) deviceClaimConfigs(ctx context.Context, claim *resourceapi.ResourceClaim) (map[string]types.DeviceConfig, error) {
	devicesCfg := map[string]types.DeviceConfig{}
	for _, cfg := range claim.Status.Allocation.Devices.Config {
		if cfg.Opaque.Parameters.Raw != nil {
			c := types.DeviceConfig{}
			if err := json.Unmarshal(cfg.Opaque.Parameters.Raw, &c); err != nil {
				driver.logger.ErrorContext(
					ctx, "failed to parse config",
					logfields.Request, cfg.Requests,
					logfields.Params, cfg.Opaque.Parameters,
					logfields.Error, err,
				)
				return nil, fmt.Errorf("failed to unmarshal config for %s: %w", path.Join(claim.Namespace, claim.Name), err)
			}
			for _, request := range cfg.Requests {
				devicesCfg[request] = c
			}
		}
	}
	return devicesCfg, nil
}

func (driver *Driver) addrsForDevice(ctx context.Context, device string, pool string) (netip.Addr, netip.Addr, error) {
	var v4Addr, v6Addr netip.Addr
	if err := resiliency.Retry(ctx, ipamRetryInterval, ipamMaxRetries, func(ctx context.Context, retries int) (bool, error) {
		var errs []error
		if driver.ipv4Enabled {
			res, err := driver.ipam.allocateNext(device, Pool(pool), IPv4, true)
			if err != nil {
				errs = append(errs, err)
			} else {
				addr, ok := netipx.FromStdIP(res.IP)
				if !ok {
					return false, fmt.Errorf("invalid IPv4 address %s", res.IP)
				}
				v4Addr = addr
			}
		}
		if driver.ipv6Enabled {
			res, err := driver.ipam.allocateNext(device, Pool(pool), IPv6, true)
			if err != nil {
				errs = append(errs, err)
			} else {
				addr, ok := netipx.FromStdIP(res.IP)
				if !ok {
					return false, fmt.Errorf("invalid IPv6 address %s", res.IP)
				}
				v6Addr = addr
			}
		}
		if len(errs) > 0 {
			driver.logger.WarnContext(
				ctx, "failed to get IP addresses for device, will retry",
				logfields.Device, device,
				logfields.PoolName, pool,
				logfields.Error, errors.Join(errs...),
			)
			return false, nil
		}
		return true, nil
	}); err != nil {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("failed to get IP addresses for device %s from pool %s", device, pool)
	}
	return v4Addr, v6Addr, nil
}

func (driver *Driver) prepareResourceClaim(ctx context.Context, claim *resourceapi.ResourceClaim) kubeletplugin.PrepareResult {
	if len(claim.Status.ReservedFor) != 1 {
		return kubeletplugin.PrepareResult{
			Err: fmt.Errorf("%w: Status.ReservedFor field has more than one entry", errUnexpectedInput),
		}
	}

	pod := claim.Status.ReservedFor[0]

	if _, ok := driver.allocations[pod.UID]; ok {
		return kubeletplugin.PrepareResult{
			Err: fmt.Errorf("%w: name: %s, resource: %s, uid: %s", errAllocationAlreadyExistsForPod, pod.Name, pod.Resource, pod.UID),
		}
	}

	deviceClaimConfigs, err := driver.deviceClaimConfigs(ctx, claim)
	if err != nil {
		return kubeletplugin.PrepareResult{Err: err}
	}

	var (
		alloc         []allocation
		devicesStatus []resourceapi.AllocatedDeviceStatus
	)

	for _, result := range claim.Status.Allocation.Devices.Results {
		var thisAlloc allocation

		cfg, ok := deviceClaimConfigs[result.Request]
		if ok {
			thisAlloc.Config = cfg
		}

		var found bool

		for mgr, devices := range driver.devices {
			for _, device := range devices {
				if device.IfName() == result.Device {
					thisAlloc.Manager = mgr
					thisAlloc.Device = device
					found = true
					break
				}
			}
		}

		if !found {
			return kubeletplugin.PrepareResult{
				Err: fmt.Errorf("%w with ifname %s for %s", errDeviceNotFound, result.Device, path.Join(claim.Namespace, claim.Name)),
			}
		}

		v4Addr, v6Addr, err := driver.addrsForDevice(ctx, result.Device, cfg.IPPool)
		if err != nil {
			driver.logger.ErrorContext(
				ctx, "failed to get IP addresses for device",
				logfields.Device, result.Device,
				logfields.PoolName, cfg.IPPool,
				logfields.Error, err,
			)
			return kubeletplugin.PrepareResult{
				Err: fmt.Errorf("failed to get IP addresses for device %s in claim %s: %w", result.Device, path.Join(claim.Namespace, claim.Name), err),
			}
		}
		thisAlloc.Config.IPv4Addr = netip.PrefixFrom(v4Addr, v4Addr.BitLen())
		thisAlloc.Config.IPv6Addr = netip.PrefixFrom(v6Addr, v6Addr.BitLen())

		if err := thisAlloc.Device.Setup(thisAlloc.Config); err != nil {
			driver.logger.ErrorContext(ctx, "failed to set up device",
				logfields.Device, thisAlloc.Device.IfName(),
				logfields.Config, thisAlloc.Config,
				logfields.Error, err,
			)

			return kubeletplugin.PrepareResult{
				Err: fmt.Errorf("%w for ifname %s on %s", err, thisAlloc.Device.IfName(), path.Join(claim.Namespace, claim.Name)),
			}
		}

		alloc = append(alloc, thisAlloc)

		dev, err := serializeDevice(thisAlloc)
		if err != nil {
			driver.logger.ErrorContext(ctx, "failed to serialize device",
				logfields.Device, thisAlloc.Device.IfName(),
				logfields.Config, thisAlloc.Config,
				logfields.Error, err,
			)

			return kubeletplugin.PrepareResult{
				Err: fmt.Errorf("failed to serialize device %s for claim %s: %w", thisAlloc.Device.IfName(), path.Join(claim.Namespace, claim.Name), err),
			}
		}

		devicesStatus = append(devicesStatus, resourceapi.AllocatedDeviceStatus{
			Driver:     driver.driverName,
			Pool:       result.Pool,
			Device:     result.Device,
			Conditions: []metav1.Condition{conditionReady(claim)},
			Data:       &runtime.RawExtension{Raw: dev},
			NetworkData: &resourceapi.NetworkDeviceData{
				InterfaceName: thisAlloc.Device.IfName(),
				IPs: []string{
					thisAlloc.Config.IPv4Addr.String(),
					thisAlloc.Config.IPv6Addr.String(),
				},
			},
		})
	}
	driver.allocations[pod.UID] = make(map[kube_types.UID][]allocation)
	driver.allocations[pod.UID][claim.UID] = alloc

	newClaim := claim.DeepCopy()
	newClaim.Status.Devices = append(newClaim.Status.Devices, devicesStatus...)
	if _, err := driver.kubeClient.ResourceV1().ResourceClaims(claim.Namespace).UpdateStatus(ctx, newClaim, metav1.UpdateOptions{}); err != nil {
		return kubeletplugin.PrepareResult{
			Err: fmt.Errorf("failed to update claim %s status: %w", path.Join(claim.Namespace, claim.Name), err),
		}
	}

	// we dont need to return anything here.
	return kubeletplugin.PrepareResult{}
}

func conditionReady(claim *resourceapi.ResourceClaim) metav1.Condition {
	return metav1.Condition{
		Type:               "Ready",
		Status:             metav1.ConditionTrue,
		Reason:             "Ready",
		Message:            "Device is ready",
		ObservedGeneration: claim.GetGeneration(),
		LastTransitionTime: metav1.NewTime(time.Now()),
	}
}

func serializeDevice(a allocation) ([]byte, error) {
	data, err := a.Device.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return json.Marshal(types.SerializedDevice{
		Manager: a.Manager,
		Dev:     data,
		Config:  a.Config,
	})
}

func deserializeDevice(data []byte) (types.DeviceManagerType, json.RawMessage, types.DeviceConfig, error) {
	var dev types.SerializedDevice

	if err := json.Unmarshal(data, &dev); err != nil {
		return types.DeviceManagerTypeUnknown, nil, types.DeviceConfig{}, err
	}

	return dev.Manager, dev.Dev, dev.Config, nil
}

// PrepareResourceClaims gets called when we have a request to allocate a resource claim. we also need to have a way to remember
// the allocations elsewhere so allocation state persist across restarts in the plugin.
func (driver *Driver) PrepareResourceClaims(ctx context.Context, claims []*resourceapi.ResourceClaim) (result map[kube_types.UID]kubeletplugin.PrepareResult, err error) {
	driver.logger.DebugContext(ctx, fmt.Sprintf("PrepareResourceClaims called with %d claims", len(claims)))

	result = make(map[kube_types.UID]kubeletplugin.PrepareResult)

	err = driver.withLock(func() error {
		for _, c := range claims {
			l := driver.logger.With(
				logfields.K8sNamespace, c.Namespace,
				logfields.UID, c.UID,
				logfields.Name, c.Name,
			)
			result[c.UID] = driver.prepareResourceClaim(ctx, c)

			l.DebugContext(ctx, "allocation for claim",
				logfields.Result, result[c.UID],
			)
		}

		return nil
	})

	return result, err
}
