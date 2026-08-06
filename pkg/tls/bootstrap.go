package tls

import (
	"context"
	"fmt"
	"os"
	"time"

	operatorv1alpha1 "github.com/openshift/api/operator/v1alpha1"
	configclient "github.com/openshift/client-go/config/clientset/versioned"
	libgoclient "github.com/openshift/library-go/pkg/config/client"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
	sigsyaml "sigs.k8s.io/yaml"
)

// ResolveFromCluster builds a client the same way controllercmd itself does
// (client.GetKubeConfigOrInClusterConfig) and fetches the operator's
// effective TLS settings from apiserver.config.openshift.io/cluster.
//
// The whole attempt -- building the client and fetching the object -- is
// retried with a short backoff, because rest.InClusterConfig() can
// transiently fail to read its projected service-account token/CA files on a
// freshly-scheduled pod before the projection is fully mounted, and the API
// server itself can be briefly unreachable during a rollout. Bounded to
// roughly 30s total via ctx; a failure after that is fatal by design, since
// this operator must never silently serve TLS settings it couldn't actually
// read.
func ResolveFromCluster(ctx context.Context, kubeConfigFile, userAgent string) (ResolvedProfile, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	var resolved ResolvedProfile
	var lastErr error
	attempt := func(ctx context.Context) (bool, error) {
		restConfig, err := libgoclient.GetKubeConfigOrInClusterConfig(kubeConfigFile, nil)
		if err != nil {
			lastErr = fmt.Errorf("failed to build kubeconfig: %w", err)
		} else if configClient, cErr := configclient.NewForConfig(rest.AddUserAgent(restConfig, userAgent)); cErr != nil {
			lastErr = fmt.Errorf("failed to create config client: %w", cErr)
		} else {
			resolved, lastErr = FetchAndResolve(ctx, configClient.ConfigV1())
		}
		if lastErr != nil {
			klog.Warningf("failed to resolve cluster TLS security profile, will retry: %v", lastErr)
			return false, nil
		}
		return true, nil
	}

	// ExponentialBackoffWithContext (rather than client-go/util/retry.OnError,
	// which isn't context-aware) stops sleeping between attempts the instant
	// ctx's 30s timeout fires, instead of finishing out a scheduled sleep
	// first. attempt reports failures via (false, nil), not (false, err), so
	// the backoff keeps retrying on them instead of treating the first one as
	// fatal; lastErr carries the actual failure through to the return below.
	backoff := wait.Backoff{Duration: 2 * time.Second, Factor: 2, Steps: 4}
	if err := wait.ExponentialBackoffWithContext(ctx, backoff, attempt); err != nil {
		if lastErr != nil {
			return ResolvedProfile{}, lastErr
		}
		return ResolvedProfile{}, err
	}
	return resolved, nil
}

// WriteConfigFile generates a GenericOperatorConfig carrying resolved's TLS
// settings, writes it to a uniquely-named temp file (the "*" in the pattern
// keeps the .yaml extension, which some YAML loaders key off of), and
// returns its path for the caller to point --config at. Returns "" without
// creating a file when resolved isn't honored, since ServingInfo wouldn't
// carry anything worth persisting.
func WriteConfigFile(resolved ResolvedProfile) (string, error) {
	if !resolved.Honor {
		return "", nil
	}

	config := &operatorv1alpha1.GenericOperatorConfig{
		TypeMeta: metav1.TypeMeta{APIVersion: operatorv1alpha1.GroupVersion.String(), Kind: "GenericOperatorConfig"},
	}
	ApplyToServingInfo(&config.ServingInfo, resolved)

	content, err := sigsyaml.Marshal(config)
	if err != nil {
		return "", fmt.Errorf("failed to marshal operator config: %w", err)
	}
	tmpFile, err := os.CreateTemp("", "sscsi-operator-config-*.yaml")
	if err != nil {
		return "", fmt.Errorf("failed to create temp config file: %w", err)
	}
	if _, err := tmpFile.Write(content); err != nil {
		tmpFile.Close()
		return "", fmt.Errorf("failed to write temp config file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return "", fmt.Errorf("failed to close temp config file: %w", err)
	}
	return tmpFile.Name(), nil
}
