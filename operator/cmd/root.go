// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	ces "github.com/cilium/cilium/operator/pkg/ciliumendpointslice"

	ipamOption "github.com/cilium/cilium/pkg/ipam/option"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/operator/pkg/ingress"
	operatorWatchers "github.com/cilium/cilium/operator/watchers"
	"github.com/cilium/cilium/pkg/ipam/allocator"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/rate"
)

var (
	// IdentityRateLimiter is a rate limiter to rate limit the number of
	// identities being GCed by the operator. See the documentation of
	// rate.Limiter to understand its difference than 'x/time/rate.Limiter'.
	//
	// With our rate.Limiter implementation Cilium will be able to handle bursts
	// of identities being garbage collected with the help of the functionality
	// provided by the 'policy-trigger-interval' in the cilium-agent. With the
	// policy-trigger even if we receive N identity changes over the interval
	// set, Cilium will only need to process all of them at once instead of
	// processing each one individually.
	IdentityRateLimiter *rate.Limiter

	operatorAddr string

	// IsLeader is an atomic boolean value that is true when the Operator is
	// elected leader. Otherwise, it is false.
	IsLeader atomic.Value
)

// Populate options required by cilium-operator command line only.
func Populate() {
	operatorAddr = viper.GetString(operatorOption.OperatorAPIServeAddr)
}

func KvstoreEnabled() bool {
	if option.Config.KVStore == "" {
		return false
	}

	return option.Config.IdentityAllocationMode == option.IdentityAllocationModeKVstore ||
		operatorOption.Config.SyncK8sServices ||
		operatorOption.Config.SyncK8sNodes
}

// OnOperatorStartLeading is the function called once the operator starts leading
// in HA mode.
func OnOperatorStartLeading(ctx context.Context) {
	IsLeader.Store(true)

	CiliumK8sClient = k8s.CiliumClient()

	// If CiliumEndpointSlice feature is enabled, create CESController, start CEP watcher and run controller.
	if !option.Config.DisableCiliumEndpointCRD && option.Config.EnableCiliumEndpointSlice {
		log.Info("Create and run CES controller, start CEP watcher")
		// Initialize  the CES controller
		cesController := ces.NewCESController(k8s.CiliumClient(),
			operatorOption.Config.CESMaxCEPsInCES,
			operatorOption.Config.CESSlicingMode,
			option.Config.K8sClientQPSLimit,
			option.Config.K8sClientBurst)
		stopCh := make(chan struct{})
		// Start CEP watcher
		operatorWatchers.CiliumEndpointsSliceInit(k8s.CiliumClient().CiliumV2(), cesController)
		// Start the CES controller, after current CEPs are synced locally in cache.
		go cesController.Run(operatorWatchers.CiliumEndpointStore, stopCh)
	}

	// Restart kube-dns as soon as possible since it helps etcd-operator to be
	// properly setup. If kube-dns is not managed by Cilium it can prevent
	// etcd from reaching out kube-dns in EKS.
	// If this logic is modified, make sure the operator's clusterrole logic for
	// pods/delete is also up-to-date.
	if option.Config.DisableCiliumEndpointCRD {
		log.Infof("KubeDNS unmanaged pods controller disabled as %q option is set to 'disabled' in Cilium ConfigMap", option.DisableCiliumEndpointCRDName)
	} else if operatorOption.Config.UnmanagedPodWatcherInterval != 0 {
		go EnableUnmanagedKubeDNSController()
	}

	var (
		nodeManager allocator.NodeEventHandler
		err         error
		withKVStore bool
	)

	log.WithField(logfields.Mode, option.Config.IPAM).Info("Initializing IPAM")

	switch ipamMode := option.Config.IPAM; ipamMode {
	case ipamOption.IPAMAzure, ipamOption.IPAMENI, ipamOption.IPAMClusterPool, ipamOption.IPAMClusterPoolV2, ipamOption.IPAMAlibabaCloud:
		alloc, providerBuiltin := AllocatorProviders[ipamMode]
		if !providerBuiltin {
			log.Fatalf("%s allocator is not supported by this version of %s", ipamMode, binaryName)
		}

		if err := alloc.Init(ctx); err != nil {
			log.WithError(err).Fatalf("Unable to init %s allocator", ipamMode)
		}

		nm, err := alloc.Start(ctx, &CiliumNodeUpdateImplementation{})
		if err != nil {
			log.WithError(err).Fatalf("Unable to start %s allocator", ipamMode)
		}

		nodeManager = nm
	}

	if operatorOption.Config.BGPAnnounceLBIP {
		log.Info("Starting LB IP allocator")
		operatorWatchers.StartLBIPAllocator(ctx, option.Config)
	}

	if KvstoreEnabled() {
		if operatorOption.Config.SyncK8sServices {
			operatorWatchers.StartSynchronizingServices(true, option.Config)
		}

		var goopts *kvstore.ExtraOptions
		scopedLog := log.WithFields(logrus.Fields{
			"kvstore": option.Config.KVStore,
			"address": option.Config.KVStoreOpt[fmt.Sprintf("%s.address", option.Config.KVStore)],
		})
		if operatorOption.Config.SyncK8sServices {
			// If K8s is enabled we can do the service translation automagically by
			// looking at services from k8s and retrieve the service IP from that.
			// This makes cilium to not depend on kube dns to interact with etcd
			if k8s.IsEnabled() {
				svcURL, isETCDOperator := kvstore.IsEtcdOperator(option.Config.KVStore, option.Config.KVStoreOpt, option.Config.K8sNamespace)
				if isETCDOperator {
					scopedLog.Infof("%s running with service synchronization: automatic etcd service translation enabled", binaryName)

					svcGetter := k8s.ServiceIPGetter(&operatorWatchers.K8sSvcCache)

					name, namespace, err := kvstore.SplitK8sServiceURL(svcURL)
					if err != nil {
						// If we couldn't derive the name/namespace for the given
						// svcURL log the error so the user can see it.
						// k8s.CreateCustomDialer won't be able to derive
						// the name/namespace as well so it does not matter that
						// we wait for all services to be synchronized with k8s.
						scopedLog.WithError(err).WithFields(logrus.Fields{
							"url": svcURL,
						}).Error("Unable to derive service name from given url")
					} else {
						scopedLog.WithFields(logrus.Fields{
							logfields.ServiceName:      name,
							logfields.ServiceNamespace: namespace,
						}).Info("Retrieving service spec from k8s to perform automatic etcd service translation")
						k8sSvc, err := k8s.Client().CoreV1().Services(namespace).Get(ctx, name, metav1.GetOptions{})
						switch {
						case err == nil:
							// Create another service cache that contains the
							// k8s service for etcd. As soon the k8s caches are
							// synced, this hijack will stop happening.
							sc := k8s.NewServiceCache(nil)
							slimSvcObj := k8s.ConvertToK8sService(k8sSvc)
							slimSvc := k8s.ObjToV1Services(slimSvcObj)
							if slimSvc == nil {
								// This will never happen but still log it
								scopedLog.Warnf("BUG: invalid k8s service: %s", slimSvcObj)
							}
							sc.UpdateService(slimSvc, nil)
							svcGetter = operatorWatchers.NewServiceGetter(&sc)
						case errors.IsNotFound(err):
							scopedLog.Error("Service not found in k8s")
						default:
							scopedLog.Warning("Unable to get service spec from k8s, this might cause network disruptions with etcd")
						}
					}

					log := log.WithField(logfields.LogSubsys, "etcd")
					goopts = &kvstore.ExtraOptions{
						DialOption: []grpc.DialOption{
							grpc.WithContextDialer(k8s.CreateCustomDialer(svcGetter, log)),
						},
					}
				}
			}
		} else {
			scopedLog.Infof("%s running without service synchronization: automatic etcd service translation disabled", binaryName)
		}
		scopedLog.Info("Connecting to kvstore")
		if err := kvstore.Setup(ctx, option.Config.KVStore, option.Config.KVStoreOpt, goopts); err != nil {
			scopedLog.WithError(err).Fatal("Unable to setup kvstore")
		}

		if operatorOption.Config.SyncK8sNodes {
			withKVStore = true
		}

		StartKvstoreWatchdog()
	}

	if k8s.IsEnabled() &&
		(operatorOption.Config.RemoveCiliumNodeTaints || operatorOption.Config.SetCiliumIsUpCondition) {
		stopCh := make(chan struct{})

		log.WithFields(logrus.Fields{
			logfields.K8sNamespace:       operatorOption.Config.CiliumK8sNamespace,
			"label-selector":             operatorOption.Config.CiliumPodLabels,
			"remove-cilium-node-taints":  operatorOption.Config.RemoveCiliumNodeTaints,
			"set-cilium-is-up-condition": operatorOption.Config.SetCiliumIsUpCondition,
		}).Info("Removing Cilium Node Taints or Setting Cilium Is Up Condition for Kubernetes Nodes")

		operatorWatchers.HandleNodeTolerationAndTaints(stopCh)
	}

	if err := StartSynchronizingCiliumNodes(ctx, nodeManager, withKVStore); err != nil {
		log.WithError(err).Fatal("Unable to setup node watcher")
	}

	if operatorOption.Config.CNPNodeStatusGCInterval != 0 {
		RunCNPNodeStatusGC(CiliumNodeStore)
	}

	if operatorOption.Config.NodeGCInterval != 0 {
		operatorWatchers.RunCiliumNodeGC(ctx, CiliumNodeStore, operatorOption.Config.NodeGCInterval)
	}

	if option.Config.IPAM == ipamOption.IPAMClusterPool || option.Config.IPAM == ipamOption.IPAMClusterPoolV2 {
		// We will use CiliumNodes as the source of truth for the podCIDRs.
		// Once the CiliumNodes are synchronized with the operator we will
		// be able to watch for K8s Node events which they will be used
		// to create the remaining CiliumNodes.
		<-K8sCiliumNodesCacheSynced

		// We don't want CiliumNodes that don't have podCIDRs to be
		// allocated with a podCIDR already being used by another node.
		// For this reason we will call Resync after all CiliumNodes are
		// synced with the operator to signal the node manager, since it
		// knows all podCIDRs that are currently set in the cluster, that
		// it can allocate podCIDRs for the nodes that don't have a podCIDR
		// set.
		nodeManager.Resync(ctx, time.Time{})
	}

	if operatorOption.Config.IdentityGCInterval != 0 {
		IdentityRateLimiter = rate.NewLimiter(
			operatorOption.Config.IdentityGCRateInterval,
			operatorOption.Config.IdentityGCRateLimit,
		)
	}

	switch option.Config.IdentityAllocationMode {
	case option.IdentityAllocationModeCRD:
		if !k8s.IsEnabled() {
			log.Fatal("CRD Identity allocation mode requires k8s to be configured.")
		}

		StartManagingK8sIdentities()

		if operatorOption.Config.IdentityGCInterval != 0 {
			go StartCRDIdentityGC()
		}
	case option.IdentityAllocationModeKVstore:
		if operatorOption.Config.IdentityGCInterval != 0 {
			StartKvstoreIdentityGC()
		}
	}

	if operatorOption.Config.EndpointGCInterval != 0 {
		EnableCiliumEndpointSyncGC(false)
	} else {
		// Even if the EndpointGC is disabled we still want it to run at least
		// once. This is to prevent leftover CEPs from populating ipcache with
		// stale entries.
		EnableCiliumEndpointSyncGC(true)
	}

	err = EnableCNPWatcher()
	if err != nil {
		log.WithError(err).WithField(logfields.LogSubsys, "CNPWatcher").Fatal(
			"Cannot connect to Kubernetes apiserver ")
	}

	err = EnableCCNPWatcher()
	if err != nil {
		log.WithError(err).WithField(logfields.LogSubsys, "CCNPWatcher").Fatal(
			"Cannot connect to Kubernetes apiserver ")
	}

	// FIXME: make sure to set operatorOption.Config.EnableIngressController to false!!!
	// As of now, we don't know how to avoid the use of RESTClient for ingresses.
	if operatorOption.Config.EnableIngressController {
		ingressController, err := ingress.NewIngressController(
			ingress.WithHTTPSEnforced(operatorOption.Config.EnforceIngressHTTPS),
			ingress.WithSecretsSyncEnabled(operatorOption.Config.EnableIngressSecretsSync),
			ingress.WithSecretsNamespace(operatorOption.Config.IngressSecretsNamespace))
		if err != nil {
			log.WithError(err).WithField(logfields.LogSubsys, ingress.Subsys).Fatal(
				"Failed to start ingress controller")
		}
		go ingressController.Run()
	}

	log.Info("Initialization complete")
}
