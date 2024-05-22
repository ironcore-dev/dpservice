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

func ListLoadBalancerPrefixes(dpdkClientFactory DPDKClientFactory, rendererFactory RendererFactory) *cobra.Command {
	var (
		opts ListLoadBalancerPrefixesOptions
	)

	cmd := &cobra.Command{
		Use:     "lbprefixes <--interface-id>",
		Short:   "List loadbalancer prefixes on interface.",
		Example: "dpservice-cli list lbprefixes --interface-id=vm1",
		Aliases: LoadBalancerPrefixAliases,
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {

			return RunListLoadBalancerPrefixes(
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

type ListLoadBalancerPrefixesOptions struct {
	InterfaceID string
	SortBy      string
}

func (o *ListLoadBalancerPrefixesOptions) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&o.InterfaceID, "interface-id", o.InterfaceID, "Interface ID of the prefix.")
	fs.StringVar(&o.SortBy, "sort-by", "", "Column to sort by.")
}

func (o *ListLoadBalancerPrefixesOptions) MarkRequiredFlags(cmd *cobra.Command) error {
	return nil
}

func RunListLoadBalancerPrefixes(
	ctx context.Context,
	dpdkClientFactory DPDKClientFactory,
	rendererFactory RendererFactory,
	opts ListLoadBalancerPrefixesOptions,
) error {
	client, cleanup, err := dpdkClientFactory.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("error creating dpdk client: %w", err)
	}
	defer DpdkClose(cleanup)

	prefixList := &api.PrefixList{
		TypeMeta: api.TypeMeta{Kind: api.PrefixListKind},
	}
	if opts.InterfaceID == "" {
		ifaces, err := client.ListInterfaces(ctx)
		if err != nil && ifaces.Status.Code == 0 {
			return fmt.Errorf("error listing interfaces: %w", err)
		}

		for _, iface := range ifaces.Items {
			prefix, err := client.ListLoadBalancerPrefixes(ctx, iface.ID)
			if err != nil && prefix.Status.Code == 0 {
				return fmt.Errorf("error getting loadbalancer prefixes: %w", err)
			}
			prefixList.Items = append(prefixList.Items, prefix.Items...)
		}
	} else {
		prefixList, err = client.ListLoadBalancerPrefixes(ctx, opts.InterfaceID)
		if err != nil {
			return fmt.Errorf("error listing loadbalancer prefixes: %w", err)
		}
	}

	// sort items in list
	prefixes := prefixList.Items
	sort.SliceStable(prefixes, func(i, j int) bool {
		mi, mj := prefixes[i], prefixes[j]
		switch strings.ToLower(opts.SortBy) {
		case "underlayroute":
			return mi.Spec.UnderlayRoute.String() < mj.Spec.UnderlayRoute.String()
		default:
			return mi.Spec.Prefix.String() < mj.Spec.Prefix.String()
		}
	})
	prefixList.Items = prefixes

	return rendererFactory.RenderList("", os.Stdout, prefixList)
}
