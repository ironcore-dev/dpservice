// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/ironcore-dev/dpservice/cli/dpservice-cli/util"
	"github.com/ironcore-dev/dpservice/go/dpservice-go/api"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func SetFirewallParams(dpdkClientFactory DPDKClientFactory, rendererFactory RendererFactory) *cobra.Command {
	var (
		opts SetFirewallParamsOptions
	)

	cmd := &cobra.Command{
		Use:     "firewallparams <--interface-id> <--firewall-state>",
		Short:   "Set firewall parameters of an interface",
		Example: "dpservice-cli set fwparams --interface-id=vm1 --firewall-state=DISABLED",
		Aliases: FirewallParamsAliases,
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunSetFirewallParams(
				cmd.Context(),
				dpdkClientFactory,
				rendererFactory,
				opts,
			)
		},
	}

	opts.AddFlags(cmd.Flags())

	util.Must(opts.MarkRequiredFlags(cmd))

	return cmd
}

type SetFirewallParamsOptions struct {
	InterfaceID   string
	FirewallState string
}

func (o *SetFirewallParamsOptions) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&o.InterfaceID, "interface-id", o.InterfaceID, "Interface ID to set the firewall parameters of.")
	// No default, the flag is required. Silently falling back to "enabled" would be a trap.
	fs.StringVar(&o.FirewallState, "firewall-state", o.FirewallState, "Firewall state for the interface (ENABLED or DISABLED).")
}

func (o *SetFirewallParamsOptions) MarkRequiredFlags(cmd *cobra.Command) error {
	for _, name := range []string{"interface-id", "firewall-state"} {
		if err := cmd.MarkFlagRequired(name); err != nil {
			return err
		}
	}
	return nil
}

func RunSetFirewallParams(
	ctx context.Context,
	dpdkClientFactory DPDKClientFactory,
	rendererFactory RendererFactory,
	opts SetFirewallParamsOptions,
) error {
	client, cleanup, err := dpdkClientFactory.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("error creating dpdk client: %w", err)
	}
	defer DpdkClose(cleanup)

	fwparams, err := client.SetFirewallParams(ctx, &api.FirewallParams{
		FirewallParamsMeta: api.FirewallParamsMeta{
			InterfaceID: opts.InterfaceID,
		},
		Spec: api.FirewallParamsSpec{
			FirewallState: opts.FirewallState,
		},
	})
	if err != nil {
		return fmt.Errorf("error setting firewall parameters: %w", err)
	}

	return rendererFactory.RenderObject("set", os.Stdout, fwparams)
}
