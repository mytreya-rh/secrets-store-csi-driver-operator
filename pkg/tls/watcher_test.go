package tls

import (
	"testing"

	configv1 "github.com/openshift/api/config/v1"
)

func TestSecurityProfileWatcherHandle(t *testing.T) {
	tests := []struct {
		name      string
		initial   ResolvedProfile
		event     *configv1.APIServer // nil simulates a Delete event
		wantFired bool
	}{
		{
			name:      "no change does not fire",
			initial:   ResolvedProfile{Honor: false, Spec: intermediateSpec()},
			event:     &configv1.APIServer{ObjectMeta: metaWithName()},
			wantFired: false,
		},
		{
			name:    "adherence flips to honoring fires",
			initial: ResolvedProfile{Honor: false, Spec: intermediateSpec()},
			event: &configv1.APIServer{
				ObjectMeta: metaWithName(),
				Spec: configv1.APIServerSpec{
					TLSAdherence: configv1.TLSAdherencePolicyStrictAllComponents,
				},
			},
			wantFired: true,
		},
		{
			name:    "profile changes while still honoring fires",
			initial: ResolvedProfile{Honor: true, Spec: intermediateSpec()},
			event: &configv1.APIServer{
				ObjectMeta: metaWithName(),
				Spec: configv1.APIServerSpec{
					TLSAdherence:       configv1.TLSAdherencePolicyStrictAllComponents,
					TLSSecurityProfile: &configv1.TLSSecurityProfile{Type: configv1.TLSProfileOldType},
				},
			},
			wantFired: true,
		},
		{
			name:      "delete event resolves back to the empty default and fires if that differs",
			initial:   ResolvedProfile{Honor: true, Spec: oldSpec()},
			event:     nil,
			wantFired: true,
		},
		{
			name:    "spec-only change while both sides are non-honoring does not fire",
			initial: ResolvedProfile{Honor: false, Spec: oldSpec()},
			event: &configv1.APIServer{
				ObjectMeta: metaWithName(),
				Spec: configv1.APIServerSpec{
					TLSAdherence:       configv1.TLSAdherencePolicyLegacyAdheringComponentsOnly,
					TLSSecurityProfile: &configv1.TLSSecurityProfile{Type: configv1.TLSProfileIntermediateType},
				},
			},
			wantFired: false,
		},
		{
			name: "unresolvable live config (Custom with nil Custom) escalates, consistent with bootstrap fail-hard policy",
			event: &configv1.APIServer{
				ObjectMeta: metaWithName(),
				Spec: configv1.APIServerSpec{
					TLSSecurityProfile: &configv1.TLSSecurityProfile{Type: configv1.TLSProfileCustomType},
				},
			},
			initial:   ResolvedProfile{Honor: false, Spec: intermediateSpec()},
			wantFired: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fired := false
			w := &SecurityProfileWatcher{
				Initial:  tt.initial,
				OnChange: func() { fired = true },
			}

			var obj interface{}
			if tt.event != nil {
				obj = tt.event
			}
			w.handle(obj)

			if fired != tt.wantFired {
				t.Errorf("fired = %v, want %v", fired, tt.wantFired)
			}
		})
	}
}

func TestSecurityProfileWatcherFiresOnlyOnce(t *testing.T) {
	fireCount := 0
	w := &SecurityProfileWatcher{
		Initial:  ResolvedProfile{Honor: false, Spec: intermediateSpec()},
		OnChange: func() { fireCount++ },
	}

	changed := &configv1.APIServer{
		ObjectMeta: metaWithName(),
		Spec:       configv1.APIServerSpec{TLSAdherence: configv1.TLSAdherencePolicyStrictAllComponents},
	}
	w.handle(changed)
	w.handle(changed)
	w.handle(nil)

	if fireCount != 1 {
		t.Errorf("OnChange fired %d times, want exactly 1", fireCount)
	}
}
