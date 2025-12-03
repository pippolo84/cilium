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
	"github.com/cilium/cilium/pkg/resiliency"
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

type ipamRequest struct {
	owner  string
	pool   string
	family Family
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

	var allocations []AllocatedDevice

	poolsForRequest := make(map[string]string)
	for _, config := range claim.Spec.Devices.Config {
		var cfg DeviceConfig
		if err := json.Unmarshal(config.Opaque.Parameters.Raw, &cfg); err != nil {
			return kubeletplugin.PrepareResult{}, fmt.Errorf("failed to unmarshal config for requests %s: %w", strings.Join(config.Requests, ","), err)
		}
		for _, req := range config.Requests {
			poolsForRequest[req] = cfg.IPPool
		}
	}

	// First collect all IPAM requests for each device request
	var (
		ipamReqsV4, ipamReqsV6 map[string][]ipamRequest
		err                    error
	)
	if driver.ipv4Enabled {
		ipamReqsV4, err = ipamRequests(claim.Spec.Devices.Requests, poolsForRequest, IPv4)
		if err != nil {
			return kubeletplugin.PrepareResult{}, fmt.Errorf("failed to parse IPAM v4 configuration: %w", err)
		}
	}
	if driver.ipv6Enabled {
		ipamReqsV6, err = ipamRequests(claim.Spec.Devices.Requests, poolsForRequest, IPv6)
		if err != nil {
			return kubeletplugin.PrepareResult{}, fmt.Errorf("failed to parse IPAM v6 configuration: %w", err)
		}
	}

	// Then try to fulfill all the requests in one go, to let the operator initiate the needed
	// CIDRs allocation to the node from all the involved pools.
	// This is needed to reduce the overall time to allocate all the addresses.
	addrsReqsV4, addrsReqsV6 := map[string][]net.IP{}, map[string][]net.IP{}
	if err := resiliency.Retry(ctx, draIPAMRetry, draIPAMMaxRetries, func(ctx context.Context, retries int) (bool, error) {
		var addrsV4, addrsV6 map[string][]net.IP
		if driver.ipv4Enabled {
			addrsV4, ipamReqsV4 = addrsAllocation(driver.ipam, ipamReqsV4)
		}
		if driver.ipv6Enabled {
			addrsV6, ipamReqsV6 = addrsAllocation(driver.ipam, ipamReqsV6)
		}
		for req, addrs := range addrsV4 {
			addrsReqsV4[req] = append(addrsReqsV4[req], addrs...)
		}
		for req, addrs := range addrsV6 {
			addrsReqsV6[req] = append(addrsReqsV6[req], addrs...)
		}
		if len(ipamReqsV4) > 0 || len(ipamReqsV6) > 0 {
			return false, nil
		}
		return true, nil
	}); err != nil {
		driver.logger.ErrorContext(ctx, "Failed to allocate IP addresses", logfields.Error, err)
		return kubeletplugin.PrepareResult{}, fmt.Errorf("failed to allocate IP addresses")
	}

	var errs []error

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

		if driver.ipv4Enabled {
			addrs, found := addrsReqsV4[allocation.Request]
			if !found || len(addrs) == 0 {
				errs = append(errs, fmt.Errorf("failed to find IP addresses for device %s from request %s", allocation.Device, allocation.Request))
				continue
			}
			device.IPv4 = addrs[0]
			addrsReqsV4[allocation.Request] = addrs[1:]
		}
		if driver.ipv6Enabled {
			addrs, found := addrsReqsV6[allocation.Request]
			if !found || len(addrs) == 0 {
				errs = append(errs, fmt.Errorf("failed to find IP addresses for device %s from request %s", allocation.Device, allocation.Request))
				continue
			}
			device.IPv6 = addrs[0]
			addrsReqsV6[allocation.Request] = addrs[1:]
		}

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

func ipamRequests(deviceReqs []resourceapi.DeviceRequest, poolsForRequest map[string]string, family Family) (map[string][]ipamRequest, error) {
	ipamReqs := map[string][]ipamRequest{}

	for _, req := range deviceReqs {
		// FIXME: add support for FirstAvailable
		if len(req.FirstAvailable) > 0 {
			return nil, errors.New("firstAvailable allocation mode not supported yet")
		}

		addrsReqs := make([]ipamRequest, 0, req.Exactly.Count)
		for i := range req.Exactly.Count {
			pool, found := poolsForRequest[req.Name]
			if !found {
				return nil, fmt.Errorf("unable to find IP pool for request %s", req.Name)
			}

			addrsReqs = append(addrsReqs, ipamRequest{
				owner:  fmt.Sprintf("%s-%d", req.Name, i),
				pool:   pool,
				family: family,
			})
		}
		ipamReqs[req.Name] = addrsReqs
	}
	return ipamReqs, nil
}

func addrsAllocation(ipam *multiPoolManager, requests map[string][]ipamRequest) (map[string][]net.IP, map[string][]ipamRequest) {
	satisfied := map[string][]net.IP{}
	unsatisfied := map[string][]ipamRequest{}

	var addrs []net.IP
	for reqName, ipamReqs := range requests {
		for _, req := range ipamReqs {
			res, err := ipam.allocateNext(req.owner, Pool(req.pool), req.family, true)
			if err != nil {
				unsatisfied[reqName] = append(unsatisfied[reqName], req)
				continue
			}
			addrs = append(addrs, res.IP)
		}
		satisfied[reqName] = addrs
	}

	return satisfied, unsatisfied
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
