package operator

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	apiserver "k8s.io/apiserver/pkg/server"
	"k8s.io/client-go/dynamic"
	kubeclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
	"k8s.io/utils/clock"

	opv1 "github.com/openshift/api/operator/v1"
	configclient "github.com/openshift/client-go/config/clientset/versioned"
	configinformers "github.com/openshift/client-go/config/informers/externalversions"
	applyoperatorv1 "github.com/openshift/client-go/operator/applyconfigurations/operator/v1"
	"github.com/openshift/library-go/pkg/controller/controllercmd"
	"github.com/openshift/library-go/pkg/operator/csi/csicontrollerset"
	"github.com/openshift/library-go/pkg/operator/csi/csidrivernodeservicecontroller"
	goc "github.com/openshift/library-go/pkg/operator/genericoperatorclient"
	"github.com/openshift/library-go/pkg/operator/management"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
	"github.com/openshift/secrets-store-csi-driver-operator/assets"
	sscsitls "github.com/openshift/secrets-store-csi-driver-operator/pkg/tls"
)

const (
	operatorName       = "secrets-store-csi-driver-operator"
	operandName        = "secrets-store-csi-driver"
	trustedCAConfigMap = "secrets-store-csi-driver-trusted-ca-bundle"
	providerName       = "secrets-store.csi.k8s.io"
	namespaceKey       = "${NAMESPACE}"
	resync             = 20 * time.Minute
)

// RunOperator wires up and runs all operator controllers. resolvedTLS is the
// cluster TLS security profile already applied to the operator's own
// HTTPServingInfo at startup (see cmd/secrets-store-csi-driver-operator);
// it's threaded through here only so the SecurityProfileWatcher below can
// diff live changes against it.
func RunOperator(
	ctx context.Context,
	controllerConfig *controllercmd.ControllerContext,
	resolvedTLS sscsitls.ResolvedProfile,
) error {
	operatorNamespace := controllerConfig.OperatorNamespace

	// Create core clientset and informers
	kubeClient := kubeclient.NewForConfigOrDie(rest.AddUserAgent(controllerConfig.KubeConfig, operatorName))
	kubeInformersForNamespaces := v1helpers.NewKubeInformersForNamespaces(kubeClient, operatorNamespace, "")
	configMapInformer := kubeInformersForNamespaces.InformersFor(operatorNamespace).Core().V1().ConfigMaps()

	// Create config clientset and informer. This is used to get the cluster ID
	configClient := configclient.NewForConfigOrDie(rest.AddUserAgent(controllerConfig.KubeConfig, operatorName))
	configInformers := configinformers.NewSharedInformerFactory(configClient, resync)

	// Create GenericOperatorclient. This is used by the library-go controllers created down below
	gvr := opv1.SchemeGroupVersion.WithResource("clustercsidrivers")
	gvk := opv1.SchemeGroupVersion.WithKind("ClusterCSIDriver")
	operatorClient, dynamicInformers, err := goc.NewClusterScopedOperatorClientWithConfigName(
		clock.RealClock{},
		controllerConfig.KubeConfig,
		gvr,
		gvk,
		providerName,
		extractOperatorSpec,
		extractOperatorStatus,
	)
	if err != nil {
		return err
	}

	dynamicClient, err := dynamic.NewForConfig(controllerConfig.KubeConfig)
	if err != nil {
		return err
	}

	// ClusterCSIDriver lister to read driverConfig.secretsStore configuration.
	// This reuses the dynamic informer/cache above (same GVR) instead of
	// standing up a second, independent informer/watch for the same
	// singleton ClusterCSIDriver object.
	clusterCSIDriverLister := newDynamicClusterCSIDriverLister(dynamicInformers.ForResource(gvr).Lister())

	// csiDriverInformer is the storage.k8s.io/v1 CSIDriver informer
	csiDriverInformer := kubeInformersForNamespaces.InformersFor("").Storage().V1().CSIDrivers()

	csiControllerSet := csicontrollerset.NewCSIControllerSet(
		operatorClient,
		controllerConfig.EventRecorder,
	).WithLogLevelController().WithManagementStateController(
		operandName,
		true, // Set this operator as removable
	).WithConditionalStaticResourcesController(
		"SecretsStoreConditionalStaticResourcesController",
		kubeClient,
		dynamicClient,
		kubeInformersForNamespaces,
		withSecretsStoreCSIDriverAsset(
			replaceNamespaceFunc(operatorNamespace),
			clusterCSIDriverLister,
			csiDriverInformer.Lister(),
			providerName,
		),
		[]string{
			"node_sa.yaml",
			"csidriver.yaml",
			"cabundle_cm.yaml",
			"rbac/privileged_role.yaml",
			"rbac/node_privileged_binding.yaml",
			"rbac/secretproviderclasses_role.yaml",
			"rbac/secretproviderclasses_binding.yaml",
			"network-policy/allow-ingress-to-metrics-operand.yaml",
		},
		func() bool {
			return getOperatorSyncState(operatorClient) == opv1.Managed
		},
		func() bool {
			return getOperatorSyncState(operatorClient) == opv1.Removed
		},
	).WithCSIConfigObserverController(
		"SecretsStoreDriverCSIConfigObserverController",
		configInformers,
	).WithCSIDriverNodeService(
		"SecretsStoreDriverNodeServiceController",
		replaceNamespaceFunc(operatorNamespace),
		"node.yaml",
		kubeClient,
		kubeInformersForNamespaces.InformersFor(operatorNamespace),
		nil,
		csidrivernodeservicecontroller.WithCABundleDaemonSetHook(
			operatorNamespace,
			trustedCAConfigMap,
			configMapInformer,
		),
		withSecretRotationDaemonSetHook(
			clusterCSIDriverLister,
			providerName,
		),
	)

	tlsWatcher := &sscsitls.SecurityProfileWatcher{
		Initial: resolvedTLS,
		OnChange: func() {
			// The HTTPS server can't be reconfigured in place, so the
			// process needs to restart. RequestShutdown emulates the same
			// SIGTERM/SIGINT that controllercmd.StartController already
			// wires up a graceful shutdown for (see cmd.go's
			// server.SetupSignalHandler()), so this goes through the same
			// context-cancellation chain as a real termination signal --
			// controllers get to unwind, and the process exits 0 via the
			// normal path -- instead of killing the process outright.
			// RequestShutdown only fails (returns false) if that signal
			// handler hasn't been installed yet, which can't happen here
			// since this watcher only starts after it has been; os.Exit(0)
			// is kept as a belt-and-suspenders fallback for that case.
			klog.Info("Cluster TLS security profile changed, restarting to apply it")
			if !apiserver.RequestShutdown() {
				klog.Warning("failed to request a graceful shutdown, exiting directly")
				os.Exit(0)
			}
		},
	}
	if err := tlsWatcher.Start(configInformers.Config().V1().APIServers()); err != nil {
		return fmt.Errorf("failed to start cluster TLS security profile watcher: %w", err)
	}

	klog.Info("Starting the informers")
	go kubeInformersForNamespaces.Start(ctx.Done())
	go dynamicInformers.Start(ctx.Done())
	go configInformers.Start(ctx.Done())

	klog.Info("Starting controllerset")
	go csiControllerSet.Run(ctx, 1)

	<-ctx.Done()

	return nil
}

func replaceNamespaceFunc(namespace string) resourceapply.AssetFunc {
	return func(name string) ([]byte, error) {
		content, err := assets.ReadFile(name)
		if err != nil {
			panic(err)
		}
		return bytes.ReplaceAll(content, []byte(namespaceKey), []byte(namespace)), nil
	}
}

// getOperatorSyncState returns the management state of the operator to determine
// how to sync conditional resources. It returns one of the following states:
//
//	Managed: resources should be synced
//	Unmanaged: resources should NOT be synced
//	Removed: resources should be deleted
//
// Errors fetching the operator state will log an error and return Unmanaged
// to avoid syncing resources when the actual state is unknown.
func getOperatorSyncState(operatorClient v1helpers.OperatorClientWithFinalizers) opv1.ManagementState {
	opSpec, _, _, err := operatorClient.GetOperatorState()
	if err != nil {
		klog.Errorf("Failed to get operator state: %v", err)
		return opv1.Unmanaged
	}
	// return the state from the operator if it's not managed
	if opSpec.ManagementState != opv1.Managed {
		return opSpec.ManagementState
	}
	meta, err := operatorClient.GetObjectMeta()
	if err != nil {
		klog.Errorf("Failed to get operator object meta: %v", err)
		return opv1.Unmanaged
	}
	// deletion timestamp is treated the same as the state being removed
	if management.IsOperatorRemovable() && meta.DeletionTimestamp != nil {
		klog.Infof("Operator deletion timestamp is set, removing conditional resources")
		return opv1.Removed
	}
	return opv1.Managed
}

func extractOperatorSpec(obj *unstructured.Unstructured, fieldManager string) (*applyoperatorv1.OperatorSpecApplyConfiguration, error) {
	castObj := &opv1.ClusterCSIDriver{}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, castObj); err != nil {
		return nil, fmt.Errorf("unable to convert to ClusterCSIDriver: %w", err)
	}
	ret, err := applyoperatorv1.ExtractClusterCSIDriver(castObj, fieldManager)
	if err != nil {
		return nil, fmt.Errorf("unable to extract fields for %q: %w", fieldManager, err)
	}
	if ret.Spec == nil {
		return nil, nil
	}
	return &ret.Spec.OperatorSpecApplyConfiguration, nil
}
func extractOperatorStatus(obj *unstructured.Unstructured, fieldManager string) (*applyoperatorv1.OperatorStatusApplyConfiguration, error) {
	castObj := &opv1.ClusterCSIDriver{}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, castObj); err != nil {
		return nil, fmt.Errorf("unable to convert to ClusterCSIDriver: %w", err)
	}
	ret, err := applyoperatorv1.ExtractClusterCSIDriverStatus(castObj, fieldManager)
	if err != nil {
		return nil, fmt.Errorf("unable to extract fields for %q: %w", fieldManager, err)
	}

	if ret.Status == nil {
		return nil, nil
	}
	return &ret.Status.OperatorStatusApplyConfiguration, nil
}
