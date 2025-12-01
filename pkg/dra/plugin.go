// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dra

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"

	resourceapi "k8s.io/api/resource/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/dynamic-resource-allocation/kubeletplugin"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

// DeviceConfig represents the configuration to be applied to devices in a claim
type DeviceConfig struct {
	IPPool string `json:"ip-pool"`
}

// AllocatedDevice represents a network device allocated to a pod with its configuration
type AllocatedDevice struct {
	Name       string
	Attributes map[resourceapi.QualifiedName]resourceapi.DeviceAttribute
	PoolName   string
	Request    string
	IPv4       net.IP
	IPv6       net.IP
}

// PrepareResourceClaims is called to prepare all resources allocated for the given ResourceClaims
func (driver *Driver) PrepareResourceClaims(ctx context.Context, claims []*resourceapi.ResourceClaim) (map[types.UID]kubeletplugin.PrepareResult, error) {
	if len(claims) == 0 {
		return nil, nil
	}

	results := make(map[types.UID]kubeletplugin.PrepareResult, len(claims))
	for _, claim := range claims {
		driver.logger.DebugContext(ctx, "PrepareResourceClaims: Claim Request",
			logfields.K8sNamespace, claim.Namespace,
			logfields.Name, claim.Name,
			logfields.UID, claim.UID,
		)

		result, err := driver.prepareResourceClaim(ctx, claim)
		if err != nil {
			driver.logger.ErrorContext(ctx, "Failed to prepare claim",
				logfields.K8sNamespace, claim.Namespace,
				logfields.Name, claim.Name,
				logfields.Error, err,
			)
			results[claim.UID] = kubeletplugin.PrepareResult{
				Err: fmt.Errorf("claim %s/%s with UID %s contains errors: %w", claim.UID, claim.Namespace, claim.Name, err),
			}
			continue
		}
		results[claim.UID] = result
	}
	return results, nil
}

// UnprepareResourceClaims must undo whatever work PrepareResourceClaims did.
func (driver *Driver) UnprepareResourceClaims(ctx context.Context, claims []kubeletplugin.NamespacedObject) (map[types.UID]error, error) {
	if len(claims) == 0 {
		return nil, nil
	}

	result := make(map[types.UID]error, len(claims))
	for _, claim := range claims {
		driver.logger.DebugContext(ctx, "UnprepareResourceClaim: Claim Request",
			logfields.K8sNamespace, claim.Namespace,
			logfields.Name, claim.Name,
			logfields.UID, claim.UID,
		)
		result[claim.UID] = driver.unprepareResourceClaim(ctx, claim)
	}

	return result, nil
}

// HandleError gets called for errors encountered in the background.
func (driver *Driver) HandleError(ctx context.Context, err error, msg string) {
	driver.logger.ErrorContext(ctx, "HandleError",
		logfields.Error, err,
		logfields.Message, msg,
	)

	// See: https://pkg.go.dev/k8s.io/apimachinery/pkg/util/runtime#HandleErrorWithContext
	runtime.HandleErrorWithContext(ctx, err, msg)
}

type ipAddrs struct {
	ipv4 net.IP
	ipv6 net.IP
}

func (driver *Driver) prepareResourceClaim(ctx context.Context, claim *resourceapi.ResourceClaim) (kubeletplugin.PrepareResult, error) {
	// Extract pod UIDs that this claim is reserved for
	podUIDs := []types.UID{}
	for _, reference := range claim.Status.ReservedFor {
		if reference.Resource != "pods" || reference.APIGroup != "" {
			driver.logger.WarnContext(ctx, "Driver only supports Pods, unsupported reference",
				logfields.K8sNamespace, claim.Namespace,
				logfields.Name, claim.Name,
				logfields.UID, claim.UID,
				logfields.Reference, reference,
			)
			continue
		}
		podUIDs = append(podUIDs, reference.UID)
	}

	if len(podUIDs) == 0 {
		driver.logger.DebugContext(ctx, "No pods referenced by the claim",
			logfields.K8sNamespace, claim.Namespace,
			logfields.Name, claim.Name,
			logfields.UID, claim.UID,
		)
		return kubeletplugin.PrepareResult{}, nil
	}

	if claim.Status.Allocation == nil || len(claim.Status.Allocation.Devices.Results) == 0 {
		driver.logger.DebugContext(ctx, "Claim has no allocated devices",
			logfields.K8sNamespace, claim.Namespace,
			logfields.Name, claim.Name,
			logfields.UID, claim.UID,
		)
		return kubeletplugin.PrepareResult{}, nil
	}

	var (
		errs        []error
		allocations []AllocatedDevice
	)

	requestsPool := make(map[string]string)
	for _, config := range claim.Spec.Devices.Config {
		var cfg DeviceConfig
		if err := json.Unmarshal(config.Opaque.Parameters.Raw, &cfg); err != nil {
			return kubeletplugin.PrepareResult{}, fmt.Errorf("failed to unmarshal config for requests %s: %w", strings.Join(config.Requests, ","), err)
		}
		for _, req := range config.Requests {
			requestsPool[req] = cfg.IPPool
		}
	}

	// For each request, allocate count IPs from the pool specified in the request config.
	reqsAddrs := make(map[string][]ipAddrs)
	for _, req := range claim.Spec.Devices.Requests {
		// FIXME: add support for FirstAvailable
		if len(req.FirstAvailable) > 0 {
			return kubeletplugin.PrepareResult{}, fmt.Errorf("firstAvailable allocation mode not supported yet")
		}

		var addrs ipAddrs
		for i := range req.Exactly.Count {
			pool, found := requestsPool[req.Name]
			if !found {
				return kubeletplugin.PrepareResult{}, fmt.Errorf("unable to find IP pool for request %s", req.Name)
			}
			if driver.ipv4Enabled {
				res, err := driver.ipam.allocateNext(fmt.Sprintf("%s-%d", req.Name, i), Pool(pool), IPv4, true)
				if err != nil {
					driver.logger.ErrorContext(ctx, "Failed to allocate IPv4 from pool",
						logfields.K8sNamespace, claim.Namespace,
						logfields.Name, claim.Name,
						logfields.Request, req.Name,
						logfields.PoolName, pool,
						logfields.Error, err,
					)
					errs = append(errs, fmt.Errorf("failed to allocate IPv4 address from pool %s for request %s", pool, req.Name))
				} else {
					addrs.ipv4 = res.IP
				}
			}
			if driver.ipv4Enabled {
				res, err := driver.ipam.allocateNext(fmt.Sprintf("%s-%d", req.Name, i), Pool(pool), IPv6, true)
				if err != nil {
					driver.logger.ErrorContext(ctx, "Failed to allocate IPv6 from pool",
						logfields.K8sNamespace, claim.Namespace,
						logfields.Name, claim.Name,
						logfields.Request, req.Name,
						logfields.PoolName, pool,
						logfields.Error, err,
					)
					errs = append(errs, fmt.Errorf("failed to allocate IPv6 address from pool %s for request %s", pool, req.Name))
				} else {
					addrs.ipv6 = res.IP
				}
			}
			reqsAddrs[req.Name] = append(reqsAddrs[req.Name], addrs)
		}
	}

	if len(errs) > 0 {
		return kubeletplugin.PrepareResult{}, errors.Join(errs...)
	}

	for _, allocation := range claim.Status.Allocation.Devices.Results {
		// filter out devices not managed by this driver
		if allocation.Driver != driver.name {
			continue
		}

		// get device attributes from published resources
		deviceAttrs, err := driver.getDeviceAttributes(ctx, allocation.Device)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to get attributes for device %s from request %s: %w", allocation.Device, allocation.Request, err))
			continue
		}

		device := AllocatedDevice{
			Name:       allocation.Device,
			Attributes: deviceAttrs,
			PoolName:   allocation.Pool,
			Request:    allocation.Request,
		}

		addrs, found := reqsAddrs[allocation.Request]
		if !found || len(addrs) == 0 {
			errs = append(errs, fmt.Errorf("failed to find IP addresses for device %s from request %s", allocation.Device, allocation.Request))
			continue
		}
		if driver.ipv4Enabled {
			device.IPv4 = addrs[0].ipv4
		}
		if driver.ipv6Enabled {
			device.IPv6 = addrs[0].ipv6
		}
		reqsAddrs[allocation.Request] = addrs[1:]

		allocations = append(allocations, device)

		driver.logger.DebugContext(ctx, "Prepared device for claim",
			logfields.Device, allocation.Device,
			logfields.Attributes, deviceAttrs,
			logfields.IPv4, device.IPv4,
			logfields.IPv6, device.IPv6,
			logfields.K8sNamespace, claim.Namespace,
			logfields.Name, claim.Name,
		)
	}

	// Store device configuration for all referenced pods
	driver.lock.Lock()
	defer driver.lock.Unlock()
	for _, podUID := range podUIDs {
		driver.podDeviceConfig[podUID] = append(driver.podDeviceConfig[podUID], allocations...)
		driver.logger.DebugContext(ctx, "Prepared devices for pod",
			logfields.UID, podUID,
			logfields.Devices, len(allocations),
		)
	}

	return kubeletplugin.PrepareResult{}, errors.Join(errs...)
}

func (driver *Driver) getDeviceAttributes(ctx context.Context, target string) (map[resourceapi.QualifiedName]resourceapi.DeviceAttribute, error) {
	// Get fresh device list to find attributes
	devices, err := driver.listDevices(ctx, driver.logger, driver.toQualifiedName)
	if err != nil {
		return nil, fmt.Errorf("failed to list devices: %w", err)
	}

	for _, device := range devices {
		if device.Name == target {
			return device.Attributes, nil
		}
	}

	return nil, fmt.Errorf("device %s not found in available devices", target)
}

func (driver *Driver) unprepareResourceClaim(ctx context.Context, claim kubeletplugin.NamespacedObject) error {
	driver.lock.Lock()
	defer driver.lock.Unlock()

	devices, ok := driver.podDeviceConfig[claim.UID]
	if !ok {
		driver.logger.DebugContext(ctx, "UnprepareResourceClaim: no devices allocated for claim",
			logfields.K8sNamespace, claim.Namespace,
			logfields.Name, claim.Name,
			logfields.UID, claim.UID,
		)
		return nil
	}

	delete(driver.podDeviceConfig, claim.UID)
	driver.logger.DebugContext(ctx, "UnprepareResourceClaim completed for claim",
		logfields.K8sNamespace, claim.Namespace,
		logfields.Name, claim.Name,
		logfields.UID, claim.UID,
		logfields.NumDevices, len(devices),
	)

	return nil
}
