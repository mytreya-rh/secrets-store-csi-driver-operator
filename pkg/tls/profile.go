// Package tls resolves the cluster-wide TLS security profile from
// apiserver.config.openshift.io/cluster and applies it to the operator's own
// HTTPS serving endpoint (metrics/healthz). It does not affect the CSI
// driver operand, which serves its metrics over plain HTTP on 8095.
package tls

import (
	"context"
	"fmt"

	configv1 "github.com/openshift/api/config/v1"
	configv1client "github.com/openshift/client-go/config/clientset/versioned/typed/config/v1"
	libgocrypto "github.com/openshift/library-go/pkg/crypto"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"
)

// APIServerName is the singleton APIServer resource name.
const APIServerName = "cluster"

// ResolvedProfile holds the operator's effective TLS settings, plus the raw
// values a SecurityProfileWatcher needs to detect a later change.
type ResolvedProfile struct {
	// Adherence is the raw tlsAdherence value from the APIServer (may be empty).
	Adherence configv1.TLSAdherencePolicy
	// Spec is the resolved TLS profile (Intermediate when unset on the APIServer).
	Spec configv1.TLSProfileSpec
	// Honor is true when the cluster profile should be applied to ServingInfo.
	// False (Legacy/empty adherence) means keep Controllercmd's own defaults.
	Honor bool
}

// FetchAndResolve loads apiserver.config.openshift.io/cluster and resolves
// the TLS profile the operator should use for its own HTTPS server.
//
// A missing APIServer object falls back to Intermediate/non-honoring
// defaults, since a from-scratch or partially-bootstrapped cluster may not
// have created it yet. Any other fetch error is returned to the caller: this
// operator must never silently serve TLS settings it couldn't actually read.
func FetchAndResolve(ctx context.Context, client configv1client.APIServersGetter) (ResolvedProfile, error) {
	apiServer, err := client.APIServers().Get(ctx, APIServerName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		klog.Warningf("apiserver.config.openshift.io/%s not found; using Intermediate TLS profile", APIServerName)
		apiServer = &configv1.APIServer{}
	} else if err != nil {
		return ResolvedProfile{}, fmt.Errorf("failed to get apiserver.config.openshift.io/%s: %w", APIServerName, err)
	}
	return resolveFromAPIServer(apiServer)
}

// resolveFromAPIServer resolves TLS settings from an already-fetched
// APIServer object. Exported as ResolveFromAPIServer below for the
// SecurityProfileWatcher, which re-resolves on every informer event instead
// of doing its own Get.
func resolveFromAPIServer(apiServer *configv1.APIServer) (ResolvedProfile, error) {
	spec, err := tlsProfileSpecFor(apiServer.Spec.TLSSecurityProfile)
	if err != nil {
		return ResolvedProfile{}, err
	}

	adherence := apiServer.Spec.TLSAdherence
	return ResolvedProfile{
		Adherence: adherence,
		Spec:      spec,
		Honor:     libgocrypto.ShouldHonorClusterTLSProfile(adherence),
	}, nil
}

// ResolveFromAPIServer is resolveFromAPIServer's exported form, used by the
// SecurityProfileWatcher to re-resolve an already-fetched informer object.
func ResolveFromAPIServer(apiServer *configv1.APIServer) (ResolvedProfile, error) {
	if apiServer == nil {
		apiServer = &configv1.APIServer{}
	}
	return resolveFromAPIServer(apiServer)
}

// tlsProfileSpecFor returns the effective TLSProfileSpec for the given
// profile. A nil/empty profile falls back to Intermediate. A Custom profile
// with a nil Custom field is a misconfigured CR and returns an error rather
// than silently falling back, since silently widening to a different profile
// is exactly the kind of mistake TLS adherence exists to prevent.
func tlsProfileSpecFor(profile *configv1.TLSSecurityProfile) (configv1.TLSProfileSpec, error) {
	defaultProfile := *configv1.TLSProfiles[libgocrypto.DefaultTLSProfileType]
	if profile == nil || profile.Type == "" {
		return defaultProfile, nil
	}
	if profile.Type == configv1.TLSProfileCustomType {
		if profile.Custom == nil {
			return configv1.TLSProfileSpec{}, fmt.Errorf("tlsSecurityProfile.type is Custom but tlsSecurityProfile.custom is unset")
		}
		return profile.Custom.TLSProfileSpec, nil
	}
	if spec, ok := configv1.TLSProfiles[profile.Type]; ok {
		return *spec, nil
	}
	klog.Warningf("apiserver.config.openshift.io/%s has unknown tlsSecurityProfile.type %q; using Intermediate", APIServerName, profile.Type)
	return defaultProfile, nil
}

// ApplyToServingInfo writes MinTLSVersion and CipherSuites into servingInfo
// when the resolved profile should be honored (Honor == true). Otherwise
// servingInfo is left untouched, so Controllercmd's recommended defaults
// remain in effect (Legacy/unset tlsAdherence).
func ApplyToServingInfo(servingInfo *configv1.HTTPServingInfo, resolved ResolvedProfile) {
	if !resolved.Honor {
		klog.Infof("TLS adherence policy is %q; using Controllercmd default TLS settings", resolved.Adherence)
		return
	}

	servingInfo.MinTLSVersion = string(resolved.Spec.MinTLSVersion)
	servingInfo.CipherSuites = libgocrypto.OpenSSLToIANACipherSuites(resolved.Spec.Ciphers)
	if len(resolved.Spec.Ciphers) > 0 && len(servingInfo.CipherSuites) == 0 {
		// Every configured cipher was unsupported by Go's crypto/tls and
		// silently dropped by OpenSSLToIANACipherSuites (logged only at
		// klog V(4)). The server now falls back to Controllercmd's own
		// default ciphers, which may be broader than the cluster's TLS
		// policy intends, so surface this loudly rather than at V(4).
		klog.Warningf("all %d cipher(s) from the cluster TLS profile are unsupported by Go's crypto/tls and were "+
			"dropped; the metrics server will use Controllercmd default ciphers instead of %v", len(resolved.Spec.Ciphers), resolved.Spec.Ciphers)
	}
	klog.Infof("Applied cluster TLS profile to metrics serving config: minTLSVersion=%s, cipherSuites=%v",
		servingInfo.MinTLSVersion, servingInfo.CipherSuites)
}
