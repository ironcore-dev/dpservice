// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/ironcore-dev/dpservice/cli/dpservice-cli/util"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func GetFirewallParams(dpdkClientFactory DPDKClientFactory, rendererFactory RendererFactory) *cobra.Command {
	var (
		opts GetFirewallParamsOptions
	)

	cmd := &cobra.Command{
		Use:     "firewallparams <--interface-id>",
		Short:   "Get firewall parameters of an interface",
		Example: "dpservice-cli get fwparams --interface-id=vm1",
		Aliases: FirewallParamsAliases,
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunGetFirewallParams(
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

type GetFirewallParamsOptions struct {
	InterfaceID string
}

func (o *GetFirewallParamsOptions) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&o.InterfaceID, "interface-id", o.InterfaceID, "Interface ID to get the firewall parameters of.")
}

func (o *GetFirewallParamsOptions) MarkRequiredFlags(cmd *cobra.Command) error {
	for _, name := range []string{"interface-id"} {
		if err := cmd.MarkFlagRequired(name); err != nil {
			return err
		}
	}
	return nil
}

func RunGetFirewallParams(
	ctx context.Context,
	dpdkClientFactory DPDKClientFactory,
	rendererFactory RendererFactory,
	opts GetFirewallParamsOptions,
) error {
	client, cleanup, err := dpdkClientFactory.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("error creating dpdk client: %w", err)
	}
	defer DpdkClose(cleanup)

	fwparams, err := client.GetFirewallParams(ctx, opts.InterfaceID)
	if err != nil {
		return fmt.Errorf("error getting firewall parameters: %w", err)
	}

	return rendererFactory.RenderObject("", os.Stdout, fwparams)
}
