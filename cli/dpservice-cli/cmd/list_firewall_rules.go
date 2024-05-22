// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/ironcore-dev/dpservice-cli/util"
	"github.com/ironcore-dev/dpservice-go/api"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func ListFirewallRules(dpdkClientFactory DPDKClientFactory, rendererFactory RendererFactory) *cobra.Command {
	var (
		opts ListFirewallRulesOptions
	)

	cmd := &cobra.Command{
		Use:     "firewallrules <--interface-id>",
		Short:   "List firewall rules on interface",
		Example: "dpservice-cli list firewallrules --interface-id=vm1",
		Aliases: FirewallRuleAliases,
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunListFirewallRules(
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

type ListFirewallRulesOptions struct {
	InterfaceID string
	SortBy      string
}

func (o *ListFirewallRulesOptions) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&o.InterfaceID, "interface-id", o.InterfaceID, "InterfaceID from which to list firewall rules.")
	fs.StringVar(&o.SortBy, "sort-by", "", "Column to sort by.")
}

func (o *ListFirewallRulesOptions) MarkRequiredFlags(cmd *cobra.Command) error {
	return nil
}

func RunListFirewallRules(
	ctx context.Context,
	dpdkClientFactory DPDKClientFactory,
	rendererFactory RendererFactory,
	opts ListFirewallRulesOptions,
) error {
	client, cleanup, err := dpdkClientFactory.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("error creating dpdk client: %w", err)
	}
	defer DpdkClose(cleanup)

	fwruleList := &api.FirewallRuleList{
		TypeMeta: api.TypeMeta{Kind: api.FirewallRuleListKind},
	}
	if opts.InterfaceID == "" {
		ifaces, err := client.ListInterfaces(ctx)
		if err != nil && ifaces.Status.Code == 0 {
			return fmt.Errorf("error listing interfaces: %w", err)
		}

		for _, iface := range ifaces.Items {
			fwrule, err := client.ListFirewallRules(ctx, iface.ID)
			if err != nil && fwrule.Status.Code == 0 {
				return fmt.Errorf("error getting firewall rules: %w", err)
			}
			fwruleList.Items = append(fwruleList.Items, fwrule.Items...)
		}
	} else {
		fwruleList, err = client.ListFirewallRules(ctx, opts.InterfaceID)
		if err != nil {
			return fmt.Errorf("error listing firewall rules: %w", err)
		}
	}

	// sort items in list
	fwrules := fwruleList.Items
	sort.SliceStable(fwrules, func(i, j int) bool {
		mi, mj := fwrules[i], fwrules[j]
		switch strings.ToLower(opts.SortBy) {
		case "direction":
			return mi.Spec.TrafficDirection < mj.Spec.TrafficDirection
		case "src", "source":
			return mi.Spec.SourcePrefix.String() < mj.Spec.SourcePrefix.String()
		case "dst", "destination":
			return mi.Spec.DestinationPrefix.String() < mj.Spec.DestinationPrefix.String()
		case "action":
			return mi.Spec.FirewallAction < mj.Spec.FirewallAction
		case "protocol":
			return mi.Spec.ProtocolFilter.String() < mj.Spec.ProtocolFilter.String()
		case "priority":
			return mi.Spec.Priority < mj.Spec.Priority
		default:
			return mi.Spec.RuleID < mj.Spec.RuleID
		}
	})
	fwruleList.Items = fwrules

	return rendererFactory.RenderList("", os.Stdout, fwruleList)
}
