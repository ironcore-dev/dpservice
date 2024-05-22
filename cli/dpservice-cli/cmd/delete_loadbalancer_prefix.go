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

func DeleteLoadBalancerPrefix(dpdkClientFactory DPDKClientFactory, rendererFactory RendererFactory) *cobra.Command {
	var (
		opts DeleteLoadBalancerPrefixOptions
	)

	cmd := &cobra.Command{
		Use:     "lbprefix <--prefix> <--interface-id>",
		Short:   "Delete a loadbalancer prefix",
		Example: "dpservice-cli delete lbprefix --prefix=ff80::1/64 --interface-id=vm1",
		Aliases: LoadBalancerPrefixAliases,
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {

			return RunDeleteLoadBalancerPrefix(
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

type DeleteLoadBalancerPrefixOptions struct {
	Prefix      netip.Prefix
	InterfaceID string
}

func (o *DeleteLoadBalancerPrefixOptions) AddFlags(fs *pflag.FlagSet) {
	flag.PrefixVar(fs, &o.Prefix, "prefix", o.Prefix, "Loadbalancer prefix to delete.")
	fs.StringVar(&o.InterfaceID, "interface-id", o.InterfaceID, "Interface ID of the loadbalancer prefix.")
}

func (o *DeleteLoadBalancerPrefixOptions) MarkRequiredFlags(cmd *cobra.Command) error {
	for _, name := range []string{"prefix", "interface-id"} {
		if err := cmd.MarkFlagRequired(name); err != nil {
			return err
		}
	}
	return nil
}

func RunDeleteLoadBalancerPrefix(ctx context.Context, dpdkClientFactory DPDKClientFactory, rendererFactory RendererFactory, opts DeleteLoadBalancerPrefixOptions) error {
	client, cleanup, err := dpdkClientFactory.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("error creating dpdk client: %w", err)
	}
	defer DpdkClose(cleanup)

	lbprefix, err := client.DeleteLoadBalancerPrefix(ctx, opts.InterfaceID, &opts.Prefix)
	if err != nil && lbprefix.Status.Code == 0 {
		return fmt.Errorf("error deleting loadbalancer prefix: %w", err)
	}

	return rendererFactory.RenderObject("deleted", os.Stdout, lbprefix)
}
