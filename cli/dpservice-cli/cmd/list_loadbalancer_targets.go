// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"fmt"
	"os"
	"sort"

	"github.com/ironcore-dev/dpservice-cli/util"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func ListLoadBalancerTargets(dpdkClientFactory DPDKClientFactory, rendererFactory RendererFactory) *cobra.Command {
	var (
		opts ListLoadBalancerTargetOptions
	)

	cmd := &cobra.Command{
		Use:     "lbtargets <--lb-id>",
		Short:   "List LoadBalancer Targets",
		Example: "dpservice-cli list lbtargets --lb-id=1",
		Aliases: LoadBalancerTargetAliases,
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {

			return RunListLoadBalancerTargets(
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

type ListLoadBalancerTargetOptions struct {
	LoadBalancerID string
	SortBy         string
}

func (o *ListLoadBalancerTargetOptions) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&o.LoadBalancerID, "lb-id", o.LoadBalancerID, "ID of the loadbalancer to get the targets for.")
	fs.StringVar(&o.SortBy, "sort-by", "", "Column to sort by.")
}

func (o *ListLoadBalancerTargetOptions) MarkRequiredFlags(cmd *cobra.Command) error {
	for _, name := range []string{"lb-id"} {
		if err := cmd.MarkFlagRequired(name); err != nil {
			return err
		}
	}
	return nil
}

func RunListLoadBalancerTargets(
	ctx context.Context,
	dpdkClientFactory DPDKClientFactory,
	rendererFactory RendererFactory,
	opts ListLoadBalancerTargetOptions,
) error {
	client, cleanup, err := dpdkClientFactory.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("error creating dpdk client: %w", err)
	}
	defer DpdkClose(cleanup)

	lbtargets, err := client.ListLoadBalancerTargets(ctx, opts.LoadBalancerID)
	if err != nil && lbtargets.Status.Code == 0 {
		return fmt.Errorf("error listing loadbalancer targets: %w", err)
	}

	// sort items in list
	targets := lbtargets.Items
	sort.SliceStable(targets, func(i, j int) bool {
		mi, mj := targets[i], targets[j]
		return mi.Spec.TargetIP.String() < mj.Spec.TargetIP.String()
	})
	lbtargets.Items = targets

	return rendererFactory.RenderList("", os.Stdout, lbtargets)
}
