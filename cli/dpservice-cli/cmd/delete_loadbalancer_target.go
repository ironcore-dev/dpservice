// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"fmt"
	"net/netip"
	"os"

	"github.com/ironcore-dev/dpservice-cli/flag"
	"github.com/ironcore-dev/dpservice-cli/util"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func DeleteLoadBalancerTarget(dpdkClientFactory DPDKClientFactory, rendererFactory RendererFactory) *cobra.Command {
	var (
		opts DeleteLoadBalancerTargetOptions
	)

	cmd := &cobra.Command{
		Use:     "lbtarget <--target-ip> <--lb-id>",
		Short:   "Delete a loadbalancer target",
		Example: "dpservice-cli delete lbtarget --target-ip=ff80::1 --lb-id=1",
		Aliases: LoadBalancerTargetAliases,
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {

			return RunDeleteLoadBalancerTarget(
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

type DeleteLoadBalancerTargetOptions struct {
	TargetIP       netip.Addr
	LoadBalancerID string
}

func (o *DeleteLoadBalancerTargetOptions) AddFlags(fs *pflag.FlagSet) {
	flag.AddrVar(fs, &o.TargetIP, "target-ip", o.TargetIP, "LoadBalancer target IP to delete.")
	fs.StringVar(&o.LoadBalancerID, "lb-id", o.LoadBalancerID, "LoadBalancerID where to delete target.")
}

func (o *DeleteLoadBalancerTargetOptions) MarkRequiredFlags(cmd *cobra.Command) error {
	for _, name := range []string{"target-ip", "lb-id"} {
		if err := cmd.MarkFlagRequired(name); err != nil {
			return err
		}
	}
	return nil
}

func RunDeleteLoadBalancerTarget(ctx context.Context, dpdkClientFactory DPDKClientFactory, rendererFactory RendererFactory, opts DeleteLoadBalancerTargetOptions) error {
	client, cleanup, err := dpdkClientFactory.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("error creating dpdk client: %w", err)
	}
	defer DpdkClose(cleanup)

	lbtarget, err := client.DeleteLoadBalancerTarget(ctx, opts.LoadBalancerID, &opts.TargetIP)
	if err != nil && lbtarget.Status.Code == 0 {
		return fmt.Errorf("error deleting neighbor nat: %w", err)
	}

	return rendererFactory.RenderObject("deleted", os.Stdout, lbtarget)
}
