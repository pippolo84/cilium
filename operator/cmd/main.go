// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sync"

	gops "github.com/google/gops/agent"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/sys/unix"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"

	"github.com/cilium/cilium/operator/api"
	operatorMetrics "github.com/cilium/cilium/operator/metrics"
	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/components"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/client"
	k8sversion "github.com/cilium/cilium/pkg/k8s/version"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/pprof"
	"github.com/cilium/cilium/pkg/rand"
	"github.com/cilium/cilium/pkg/version"
)

var (
	leaderElectionResourceLockName = "cilium-operator-resource-lock"

	binaryName = filepath.Base(os.Args[0])

	log = logging.DefaultLogger.WithField(logfields.LogSubsys, binaryName)

	rootCmd = &cobra.Command{
		Use:   binaryName,
		Short: "Run " + binaryName,
		Run: func(cobraCmd *cobra.Command, args []string) {
			cmdRefDir := viper.GetString(option.CMDRef)
			if cmdRefDir != "" {
				GenMarkdown(cobraCmd, cmdRefDir)
				os.Exit(0)
			}

			// Open socket for using gops to get stacktraces of the agent.
			addr := fmt.Sprintf("127.0.0.1:%d", viper.GetInt(option.GopsPort))
			addrField := logrus.Fields{"address": addr}
			if err := gops.Listen(gops.Options{
				Addr:                   addr,
				ReuseSocketAddrAndPort: true,
			}); err != nil {
				log.WithError(err).WithFields(addrField).Fatal("Cannot start gops server")
			}
			log.WithFields(addrField).Info("Started gops server")

			initEnv()
			runOperator()
		},
	}

	shutdownSignal = make(chan struct{})

	// Use a Go context so we can tell the leaderelection code when we
	// want to step down
	leaderElectionCtx, leaderElectionCtxCancel = context.WithCancel(context.Background())

	doOnce sync.Once
)

func Execute() {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, unix.SIGINT, unix.SIGTERM)

	go func() {
		<-signals
		doCleanup(0)
	}()

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(MetricsCmd)
}

func initEnv() {
	// Prepopulate option.Config with options from CLI.
	option.Config.Populate()
	operatorOption.Config.Populate()

	// add hooks after setting up metrics in the option.Confog
	logging.DefaultLogger.Hooks.Add(metrics.NewLoggingHook(components.CiliumOperatortName))

	// Logging should always be bootstrapped first. Do not add any code above this!
	if err := logging.SetupLogging(option.Config.LogDriver, logging.LogOptions(option.Config.LogOpt), binaryName, option.Config.Debug); err != nil {
		log.Fatal(err)
	}

	option.LogRegisteredOptions(log)
	// Enable fallback to direct API probing to check for support of Leases in
	// case Discovery API fails.
	option.Config.EnableK8sLeasesFallbackDiscovery()
}

func initK8s(k8sInitDone chan struct{}) {
	k8s.Configure(
		option.Config.K8sAPIServer,
		option.Config.K8sKubeConfigPath,
		float32(option.Config.K8sClientQPSLimit),
		option.Config.K8sClientBurst,
	)

	if err := k8s.Init(option.Config); err != nil {
		log.WithError(err).Fatal("Unable to connect to Kubernetes apiserver")
	}

	close(k8sInitDone)
}

func doCleanup(exitCode int) {
	// We run the cleanup logic only once. The operator is assumed to exit
	// once the cleanup logic is executed.
	doOnce.Do(func() {
		IsLeader.Store(false)
		gops.Close()
		close(shutdownSignal)

		// Cancelling this conext here makes sure that if the operator hold the
		// leader lease, it will be released.
		leaderElectionCtxCancel()

		// If the exit code is set to 0, then we assume that the operator will
		// exit gracefully once the lease has been released.
		if exitCode != 0 {
			os.Exit(exitCode)
		}
	})
}

func getAPIServerAddr() []string {
	if operatorOption.Config.OperatorAPIServeAddr == "" {
		return []string{"127.0.0.1:0", "[::1]:0"}
	}
	return []string{operatorOption.Config.OperatorAPIServeAddr}
}

// checkStatus checks the connection status to the kvstore and
// k8s apiserver and returns an error if any of them is unhealthy
func checkStatus() error {
	if KvstoreEnabled() {
		// We check if we are the leader here because only the leader has
		// access to the kvstore client. Otherwise, the kvstore client check
		// will block. It is safe for a non-leader to skip this check, as the
		// it is the leader's responsibility to report the status of the
		// kvstore client.
		if leader, ok := IsLeader.Load().(bool); ok && leader {
			if client := kvstore.Client(); client == nil {
				return fmt.Errorf("kvstore client not configured")
			} else if _, err := client.Status(); err != nil {
				return err
			}
		}
	}

	if _, err := k8s.Client().Discovery().ServerVersion(); err != nil {
		return err
	}

	return nil
}

// runOperator implements the logic of leader election for cilium-operator using
// built-in leader election capbility in kubernetes.
// See: https://github.com/kubernetes/client-go/blob/master/examples/leader-election/main.go
func runOperator() {
	log.Infof("Cilium Operator %s", version.Version)
	k8sInitDone := make(chan struct{})
	IsLeader.Store(false)

	// Configure API server for the operator.
	srv, err := api.NewServer(shutdownSignal, k8sInitDone, getAPIServerAddr()...)
	if err != nil {
		log.WithError(err).Fatalf("Unable to create operator apiserver")
	}

	go func() {
		err = srv.WithStatusCheckFunc(checkStatus).StartServer()
		if err != nil {
			log.WithError(err).Fatalf("Unable to start operator apiserver")
		}
	}()

	if operatorOption.Config.EnableMetrics {
		operatorMetrics.Register()
	}

	if operatorOption.Config.PProf {
		pprof.Enable(operatorOption.Config.PProfPort)
	}

	initK8s(k8sInitDone)

	capabilities := k8sversion.Capabilities()
	if !capabilities.MinimalVersionMet {
		log.Fatalf("Minimal kubernetes version not met: %s < %s",
			k8sversion.Version(), k8sversion.MinimalVersionConstraint)
	}

	// Register the CRDs after validating that we are running on a supported
	// version of K8s.
	if !operatorOption.Config.SkipCRDCreation {
		if err := client.RegisterCRDs(); err != nil {
			log.WithError(err).Fatal("Unable to register CRDs")
		}
	} else {
		log.Info("Skipping creation of CRDs")
	}

	// We only support Operator in HA mode for Kubernetes Versions having support for
	// LeasesResourceLock.
	// See docs on capabilities.LeasesResourceLock for more context.
	if !capabilities.LeasesResourceLock {
		log.Info("Support for coordination.k8s.io/v1 not present, fallback to non HA mode")
		onOperatorStart(leaderElectionCtx)
		return
	}

	// Get hostname for identity name of the lease lock holder.
	// We identify the leader of the operator cluster using hostname.
	operatorID, err := os.Hostname()
	if err != nil {
		log.WithError(err).Fatal("Failed to get hostname when generating lease lock identity")
	}
	operatorID = rand.RandomStringWithPrefix(operatorID+"-", 10)

	ns := option.Config.K8sNamespace
	// If due to any reason the CILIUM_K8S_NAMESPACE is not set we assume the operator
	// to be in default namespace.
	if ns == "" {
		ns = metav1.NamespaceDefault
	}

	leResourceLock := &resourcelock.LeaseLock{
		LeaseMeta: metav1.ObjectMeta{
			Name:      leaderElectionResourceLockName,
			Namespace: ns,
		},
		Client: k8s.Client().CoordinationV1(),
		LockConfig: resourcelock.ResourceLockConfig{
			// Identity name of the lock holder
			Identity: operatorID,
		},
	}

	// Start the leader election for running cilium-operators
	leaderelection.RunOrDie(leaderElectionCtx, leaderelection.LeaderElectionConfig{
		Name: leaderElectionResourceLockName,

		Lock:            leResourceLock,
		ReleaseOnCancel: true,

		LeaseDuration: operatorOption.Config.LeaderElectionLeaseDuration,
		RenewDeadline: operatorOption.Config.LeaderElectionRenewDeadline,
		RetryPeriod:   operatorOption.Config.LeaderElectionRetryPeriod,

		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: onOperatorStart,
			OnStoppedLeading: func() {
				log.WithField("operator-id", operatorID).Info("Leader election lost")
				// Cleanup everything here, and exit.
				doCleanup(1)
			},
			OnNewLeader: func(identity string) {
				if identity == operatorID {
					log.Info("Leading the operator HA deployment")
				} else {
					log.WithFields(logrus.Fields{
						"newLeader":  identity,
						"operatorID": operatorID,
					}).Info("Leader re-election complete")
				}
			},
		},
	})
}

func onOperatorStart(ctx context.Context) {
	OnOperatorStartLeading(ctx)

	<-shutdownSignal
	// graceful exit
	log.Info("Received termination signal. Shutting down")
}
