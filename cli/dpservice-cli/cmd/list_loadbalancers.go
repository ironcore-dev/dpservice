// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/ironcore-dev/dpservice/cli/dpservice-cli/util"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func ListLoadBalancers(dpdkClientFactory DPDKClientFactory, rendererFactory RendererFactory) *cobra.Command {
	var (
		opts ListLoadBalancersOptions
	)

	cmd := &cobra.Command{
		Use:     "loadbalancers",
		Short:   "List all loadbalancers",
		Example: "dpservice-cli list loadbalancers",
		Aliases: LoadBalancerAliases,
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunListLoadBalancers(
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

type ListLoadBalancersOptions struct {
	SortBy string
}

func (o *ListLoadBalancersOptions) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&o.SortBy, "sort-by", "", "Column to sort by.")
}

func (o *ListLoadBalancersOptions) MarkRequiredFlags(cmd *cobra.Command) error {
	return nil
}

func RunListLoadBalancers(
	ctx context.Context,
	dpdkClientFactory DPDKClientFactory,
	rendererFactory RendererFactory,
	opts ListLoadBalancersOptions,
) error {
	client, cleanup, err := dpdkClientFactory.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("error getting dpdk client: %w", err)
	}
	defer DpdkClose(cleanup)

	loadbalancerList, err := client.ListLoadBalancers(ctx)
	if err != nil {
		return fmt.Errorf("error listing loadbalancers: %w", err)
	}

	// sort items in list
	loadbalancers := loadbalancerList.Items
	sort.SliceStable(loadbalancers, func(i, j int) bool {
		mi, mj := loadbalancers[i], loadbalancers[j]
		switch strings.ToLower(opts.SortBy) {
		case "vni":
			if mi.Spec.VNI != mj.Spec.VNI {
				return mi.Spec.VNI < mj.Spec.VNI
			}
			return mi.Spec.LbVipIP.String() < mj.Spec.LbVipIP.String()
		case "ip":
			if mi.Spec.LbVipIP.String() != mj.Spec.LbVipIP.String() {
				return mi.Spec.LbVipIP.String() < mj.Spec.LbVipIP.String()
			}
			return mi.Spec.VNI < mj.Spec.VNI
		case "underlayroute":
			return mi.Spec.UnderlayRoute.String() < mj.Spec.UnderlayRoute.String()
		default:
			return mi.ID < mj.ID
		}
	})
	loadbalancerList.Items = loadbalancers

	return rendererFactory.RenderList("", os.Stdout, loadbalancerList)
}
