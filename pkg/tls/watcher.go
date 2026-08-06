package tls

import (
	"reflect"

	configv1 "github.com/openshift/api/config/v1"
	configv1informers "github.com/openshift/client-go/config/informers/externalversions/config/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
)

// SecurityProfileWatcher reacts to live changes of apiserver.config.openshift.io/cluster's
// TLS settings by invoking OnChange, so the operator process can be restarted
// to pick up the new profile. Controllercmd's HTTPS server has no in-place
// TLS reconfiguration, so a restart is the only way to apply a change.
type SecurityProfileWatcher struct {
	// Initial is the profile that was already applied to ServingInfo at
	// startup, used as the baseline to diff subsequent informer events
	// against.
	Initial ResolvedProfile
	// OnChange is invoked (at most once) when the live profile diverges from
	// Initial, or when it can no longer be resolved at all. It must not
	// block.
	OnChange func()

	fired bool
}

// Start registers the watcher's event handler on the given APIServer
// informer. Call once, before the informer factory is started.
func (w *SecurityProfileWatcher) Start(informer configv1informers.APIServerInformer) error {
	_, err := informer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { w.handle(obj) },
		UpdateFunc: func(_, obj interface{}) { w.handle(obj) },
		DeleteFunc: func(obj interface{}) { w.handle(nil) },
	})
	return err
}

func (w *SecurityProfileWatcher) handle(obj interface{}) {
	if w.fired {
		return
	}

	var apiServer *configv1.APIServer
	if obj != nil {
		var ok bool
		apiServer, ok = obj.(*configv1.APIServer)
		if !ok {
			klog.Warningf("SecurityProfileWatcher: unexpected object type %T", obj)
			return
		}
	}

	resolved, err := ResolveFromAPIServer(apiServer)
	if err != nil {
		// Consistent with the bootstrap fail-hard policy in FetchAndResolve:
		// an unresolvable live config means we can no longer vouch for the
		// serving TLS settings being correct, so escalate the same way a
		// bootstrap failure would.
		klog.Errorf("SecurityProfileWatcher: failed to resolve TLS profile, restarting to re-resolve: %v", err)
		w.fire()
		return
	}

	// ApplyToServingInfo ignores Spec entirely while Honor is false, so a
	// Spec-only change on the non-honoring side of a Honor==false-on-both
	// comparison would apply nothing new; only restart for it when at least
	// one side actually honors the profile.
	specChanged := (resolved.Honor || w.Initial.Honor) && !reflect.DeepEqual(resolved.Spec, w.Initial.Spec)
	if resolved.Honor != w.Initial.Honor || specChanged {
		klog.Infof("Cluster TLS security profile changed (honor=%v spec=%+v); restarting to apply it", resolved.Honor, resolved.Spec)
		w.fire()
	}
}

func (w *SecurityProfileWatcher) fire() {
	w.fired = true
	w.OnChange()
}
