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

func GetFirewallRule(dpdkClientFactory DPDKClientFactory, rendererFactory RendererFactory) *cobra.Command {
	var (
		opts GetFirewallRuleOptions
	)

	cmd := &cobra.Command{
		Use:     "firewallrule <--rule-id> <--interface-id>",
		Short:   "Get firewall rule",
		Example: "dpservice-cli get fwrule --rule-id=1 --interface-id=vm1",
		Aliases: FirewallRuleAliases,
		Args:    cobra.ExactArgs(0),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			filter, _ := cmd.Flags().GetString("rule-id")
			if filter != "" {
				if err := cmd.MarkFlagRequired("interface-id"); err != nil {
					return err
				}
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {

			return RunGetFirewallRule(
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

type GetFirewallRuleOptions struct {
	RuleID      string
	InterfaceID string
}

func (o *GetFirewallRuleOptions) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&o.RuleID, "rule-id", o.RuleID, "Rule ID to get.")
	fs.StringVar(&o.InterfaceID, "interface-id", o.InterfaceID, "Interface ID where is firewall rule.")
}

func (o *GetFirewallRuleOptions) MarkRequiredFlags(cmd *cobra.Command) error {
	return nil
}

func RunGetFirewallRule(
	ctx context.Context,
	dpdkClientFactory DPDKClientFactory,
	rendererFactory RendererFactory,
	opts GetFirewallRuleOptions,
) error {
	client, cleanup, err := dpdkClientFactory.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("error creating dpdk client: %w", err)
	}
	defer DpdkClose(cleanup)

	if opts.RuleID == "" {
		return RunListFirewallRules(
			ctx,
			dpdkClientFactory,
			rendererFactory,
			ListFirewallRulesOptions{InterfaceID: opts.InterfaceID},
		)
	} else {
		fwrule, err := client.GetFirewallRule(ctx, opts.InterfaceID, opts.RuleID)
		if err != nil && fwrule.Status.Code == 0 {
			return fmt.Errorf("error getting firewall rule: %w", err)
		}

		return rendererFactory.RenderObject("", os.Stdout, fwrule)
	}
}
