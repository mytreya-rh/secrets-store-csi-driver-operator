package tls

import (
	"context"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
	fakeconfigclient "github.com/openshift/client-go/config/clientset/versioned/fake"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func intermediateSpec() configv1.TLSProfileSpec {
	return *configv1.TLSProfiles[configv1.TLSProfileIntermediateType]
}

func oldSpec() configv1.TLSProfileSpec {
	return *configv1.TLSProfiles[configv1.TLSProfileOldType]
}

func TestFetchAndResolve(t *testing.T) {
	tests := []struct {
		name      string
		apiServer *configv1.APIServer // nil means the object isn't created (NotFound)
		wantErr   bool
		want      ResolvedProfile
	}{
		{
			name:      "missing APIServer falls back to Intermediate, non-honoring",
			apiServer: nil,
			want:      ResolvedProfile{Adherence: "", Spec: intermediateSpec(), Honor: false},
		},
		{
			name: "empty spec falls back to Intermediate, non-honoring (LegacyAdheringComponentsOnly default)",
			apiServer: &configv1.APIServer{
				ObjectMeta: metaWithName(),
			},
			want: ResolvedProfile{Adherence: "", Spec: intermediateSpec(), Honor: false},
		},
		{
			name: "StrictAllComponents with Old profile is honored",
			apiServer: &configv1.APIServer{
				ObjectMeta: metaWithName(),
				Spec: configv1.APIServerSpec{
					TLSAdherence:       configv1.TLSAdherencePolicyStrictAllComponents,
					TLSSecurityProfile: &configv1.TLSSecurityProfile{Type: configv1.TLSProfileOldType},
				},
			},
			want: ResolvedProfile{Adherence: configv1.TLSAdherencePolicyStrictAllComponents, Spec: oldSpec(), Honor: true},
		},
		{
			name: "LegacyAdheringComponentsOnly is never honored regardless of profile",
			apiServer: &configv1.APIServer{
				ObjectMeta: metaWithName(),
				Spec: configv1.APIServerSpec{
					TLSAdherence:       configv1.TLSAdherencePolicyLegacyAdheringComponentsOnly,
					TLSSecurityProfile: &configv1.TLSSecurityProfile{Type: configv1.TLSProfileOldType},
				},
			},
			want: ResolvedProfile{Adherence: configv1.TLSAdherencePolicyLegacyAdheringComponentsOnly, Spec: oldSpec(), Honor: false},
		},
		{
			name: "unknown tlsAdherence value is treated as honoring (fail-secure)",
			apiServer: &configv1.APIServer{
				ObjectMeta: metaWithName(),
				Spec: configv1.APIServerSpec{
					TLSAdherence: configv1.TLSAdherencePolicy("SomeFutureValue"),
				},
			},
			want: ResolvedProfile{Adherence: configv1.TLSAdherencePolicy("SomeFutureValue"), Spec: intermediateSpec(), Honor: true},
		},
		{
			name: "Custom type with nil Custom field is a hard error, not a silent fallback",
			apiServer: &configv1.APIServer{
				ObjectMeta: metaWithName(),
				Spec: configv1.APIServerSpec{
					TLSSecurityProfile: &configv1.TLSSecurityProfile{Type: configv1.TLSProfileCustomType},
				},
			},
			wantErr: true,
		},
		{
			name: "unrecognized profile type falls back to Intermediate",
			apiServer: &configv1.APIServer{
				ObjectMeta: metaWithName(),
				Spec: configv1.APIServerSpec{
					TLSSecurityProfile: &configv1.TLSSecurityProfile{Type: configv1.TLSProfileType("Bogus")},
				},
			},
			want: ResolvedProfile{Adherence: "", Spec: intermediateSpec(), Honor: false},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			objs := []runtime.Object{}
			if tt.apiServer != nil {
				objs = append(objs, tt.apiServer)
			}
			client := fakeconfigclient.NewClientset(objs...)

			got, err := FetchAndResolve(context.Background(), client.ConfigV1())
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Adherence != tt.want.Adherence || got.Honor != tt.want.Honor || !specEqual(got.Spec, tt.want.Spec) {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestApplyToServingInfo(t *testing.T) {
	tests := []struct {
		name           string
		resolved       ResolvedProfile
		wantMinVersion string
		wantCiphers    []string
	}{
		{
			name:           "not honoring leaves ServingInfo untouched",
			resolved:       ResolvedProfile{Honor: false, Spec: oldSpec()},
			wantMinVersion: "",
			wantCiphers:    nil,
		},
		{
			name:           "honoring Intermediate applies its min version and ciphers",
			resolved:       ResolvedProfile{Honor: true, Spec: intermediateSpec()},
			wantMinVersion: string(intermediateSpec().MinTLSVersion),
			wantCiphers:    []string{"non-empty"}, // checked for non-empty below, exact list is library-go's concern
		},
		{
			name: "all ciphers unsupported by Go falls back to empty CipherSuites without panicking",
			resolved: ResolvedProfile{
				Honor: true,
				Spec: configv1.TLSProfileSpec{
					MinTLSVersion: configv1.VersionTLS12,
					Ciphers:       []string{"TOTALLY-BOGUS-CIPHER"},
				},
			},
			wantMinVersion: "VersionTLS12",
			wantCiphers:    []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			servingInfo := &configv1.HTTPServingInfo{}
			ApplyToServingInfo(servingInfo, tt.resolved)

			if servingInfo.MinTLSVersion != tt.wantMinVersion {
				t.Errorf("MinTLSVersion = %q, want %q", servingInfo.MinTLSVersion, tt.wantMinVersion)
			}
			if tt.name == "honoring Intermediate applies its min version and ciphers" {
				if len(servingInfo.CipherSuites) == 0 {
					t.Errorf("expected non-empty CipherSuites for Intermediate profile")
				}
				return
			}
			if !stringsEqual(servingInfo.CipherSuites, tt.wantCiphers) {
				t.Errorf("CipherSuites = %v, want %v", servingInfo.CipherSuites, tt.wantCiphers)
			}
		})
	}
}

func metaWithName() metav1.ObjectMeta {
	return metav1.ObjectMeta{Name: APIServerName}
}

func specEqual(a, b configv1.TLSProfileSpec) bool {
	if a.MinTLSVersion != b.MinTLSVersion || len(a.Ciphers) != len(b.Ciphers) {
		return false
	}
	for i := range a.Ciphers {
		if a.Ciphers[i] != b.Ciphers[i] {
			return false
		}
	}
	return true
}

func stringsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
