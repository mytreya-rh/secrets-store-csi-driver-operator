package main

import (
	"context"
	"fmt"
	"os"

	"github.com/openshift/library-go/pkg/controller/controllercmd"
	"github.com/spf13/cobra"
	"k8s.io/component-base/cli"
	"k8s.io/klog/v2"
	"k8s.io/utils/clock"

	"github.com/openshift/secrets-store-csi-driver-operator/pkg/operator"
	sscsitls "github.com/openshift/secrets-store-csi-driver-operator/pkg/tls"
	"github.com/openshift/secrets-store-csi-driver-operator/pkg/version"
)

const componentName = "secrets-store-csi-driver-operator"

func main() {
	command := NewOperatorCommand()
	code := cli.Run(command)
	os.Exit(code)
}

func NewOperatorCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "secrets-store-csi-driver-operator",
		Short: "OpenShift Secrets Store CSI Driver Operator",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
			os.Exit(1)
		},
	}
	cmd.AddCommand(newStartCommand())
	return cmd
}

// newStartCommand builds the stock controllercmd "start" command unchanged,
// and adds a PersistentPreRunE that resolves the cluster-wide TLS security
// profile and feeds it in through the same --config mechanism
// StartController already reads. This avoids re-implementing
// StartController (vendor/github.com/openshift/library-go/pkg/controller/controllercmd/cmd.go)
// just to reach its ServingInfo, at the cost of one indirection: the profile
// is threaded to RunOperator via a variable that PersistentPreRunE fills in
// before Run (and therefore startFunc) executes -- cobra runs the two
// strictly in that order on the same goroutine, so no synchronization is
// needed.
func newStartCommand() *cobra.Command {
	var resolvedTLS sscsitls.ResolvedProfile

	startFunc := func(ctx context.Context, controllerContext *controllercmd.ControllerContext) error {
		return operator.RunOperator(ctx, controllerContext, resolvedTLS)
	}
	cmdcfg := controllercmd.NewControllerCommandConfig(componentName, version.Get(), startFunc, clock.RealClock{})

	cmd := cmdcfg.NewCommand()
	cmd.Use = "start"
	cmd.Short = "Start the Secrets Store CSI Driver Operator"

	// StartController's own command doesn't set PersistentPreRunE as of this
	// writing, but chain into whatever is already there instead of
	// overwriting it outright, so a future library-go change (or another
	// caller of NewCommand) doesn't get silently dropped.
	existingPreRunE := cmd.PersistentPreRunE
	cmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		if existingPreRunE != nil {
			if err := existingPreRunE(cmd, args); err != nil {
				return err
			}
		}
		kubeConfigFile, err := cmd.Flags().GetString("kubeconfig")
		if err != nil {
			return err
		}
		resolvedTLS, err = sscsitls.ResolveFromCluster(context.Background(), kubeConfigFile, componentName)
		if err != nil {
			return fmt.Errorf("failed to resolve cluster TLS security profile: %w", err)
		}
		return applyTLSProfileToConfigFlag(cmd, resolvedTLS)
	}

	return cmd
}

// applyTLSProfileToConfigFlag points --config at a generated config file
// carrying resolved's TLS settings, so StartController's own (unmodified)
// config parsing picks it up a moment later. Building that file is
// sscsitls.WriteConfigFile's job; this function only owns the Cobra
// flag/CLI-wiring side of it, per this repo's cmd/ vs pkg/ split.
//
// This intentionally errors out if --config is already set rather than
// merging into the existing file: the shipped operator is always started via
// its CSV, which never passes --config, and nothing else in this repo needs
// to today either. Once something needs both --config and TLS adherence at
// the same time, add the merge logic then, informed by whatever that config
// actually needs to carry.
func applyTLSProfileToConfigFlag(cmd *cobra.Command, resolved sscsitls.ResolvedProfile) error {
	if !resolved.Honor {
		klog.Infof("TLS adherence policy is %q; leaving --config as-is", resolved.Adherence)
		return nil
	}

	configFile, err := cmd.Flags().GetString("config")
	if err != nil {
		return err
	}
	if configFile != "" {
		return fmt.Errorf("cannot apply cluster TLS security profile: --config %q is already set and merging "+
			"into an existing config file is not yet supported", configFile)
	}

	tmpFile, err := sscsitls.WriteConfigFile(resolved)
	if err != nil {
		return err
	}
	return cmd.Flags().Set("config", tmpFile)
}
