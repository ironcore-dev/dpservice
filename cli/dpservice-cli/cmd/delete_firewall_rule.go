// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/ironcore-dev/dpservice-cli/util"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func DeleteFirewallRule(dpdkClientFactory DPDKClientFactory, rendererFactory RendererFactory) *cobra.Command {
	var (
		opts DeleteFirewallRuleOptions
	)

	cmd := &cobra.Command{
		Use:     "firewallrule <--rule-id> <--interface-id>",
		Short:   "Delete firewall rule from interface",
		Example: "dpservice-cli delete firewallrule --rule-id=1 --interface-id=vm1",
		Aliases: FirewallRuleAliases,
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {

			return RunDeleteFirewallRule(
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

type DeleteFirewallRuleOptions struct {
	RuleID      string
	InterfaceID string
}

func (o *DeleteFirewallRuleOptions) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&o.RuleID, "rule-id", o.RuleID, "Rule ID to delete.")
	fs.StringVar(&o.InterfaceID, "interface-id", o.InterfaceID, "Intreface ID where to delete firewall rule.")
}

func (o *DeleteFirewallRuleOptions) MarkRequiredFlags(cmd *cobra.Command) error {
	for _, name := range []string{"rule-id", "interface-id"} {
		if err := cmd.MarkFlagRequired(name); err != nil {
			return err
		}
	}
	return nil
}

func RunDeleteFirewallRule(ctx context.Context, dpdkClientFactory DPDKClientFactory, rendererFactory RendererFactory, opts DeleteFirewallRuleOptions) error {
	client, cleanup, err := dpdkClientFactory.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("error creating dpdk client: %w", err)
	}
	defer DpdkClose(cleanup)

	fwrule, err := client.DeleteFirewallRule(ctx, opts.InterfaceID, opts.RuleID)
	if err != nil && fwrule.Status.Code == 0 {
		return fmt.Errorf("error deleting firewall rule: %w", err)
	}

	return rendererFactory.RenderObject("deleted", os.Stdout, fwrule)
}
