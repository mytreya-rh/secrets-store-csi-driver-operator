package tls

import (
	"os"
	"testing"

	operatorv1alpha1 "github.com/openshift/api/operator/v1alpha1"
	sigsyaml "sigs.k8s.io/yaml"
)

func TestWriteConfigFile(t *testing.T) {
	t.Run("not honoring writes no file", func(t *testing.T) {
		path, err := WriteConfigFile(ResolvedProfile{Honor: false, Spec: oldSpec()})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if path != "" {
			t.Errorf("path = %q, want empty", path)
			os.Remove(path)
		}
	})

	t.Run("honoring writes a config file carrying the resolved TLS settings", func(t *testing.T) {
		resolved := ResolvedProfile{Honor: true, Spec: intermediateSpec()}
		path, err := WriteConfigFile(resolved)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer os.Remove(path)

		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("failed to read %q: %v", path, err)
		}
		var config operatorv1alpha1.GenericOperatorConfig
		if err := sigsyaml.Unmarshal(content, &config); err != nil {
			t.Fatalf("failed to unmarshal written config: %v", err)
		}
		if config.ServingInfo.MinTLSVersion != string(resolved.Spec.MinTLSVersion) {
			t.Errorf("MinTLSVersion = %q, want %q", config.ServingInfo.MinTLSVersion, resolved.Spec.MinTLSVersion)
		}
		if len(config.ServingInfo.CipherSuites) == 0 {
			t.Errorf("expected non-empty CipherSuites")
		}
	})
}
