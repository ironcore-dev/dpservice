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

func DeleteRoute(dpdkClientFactory DPDKClientFactory, rendererFactory RendererFactory) *cobra.Command {
	var (
		opts DeleteRouteOptions
	)

	cmd := &cobra.Command{
		Use:     "route <--prefix> <--vni>",
		Short:   "Delete a route",
		Example: "dpservice-cli delete route --prefix=10.100.2.0/24 --vni=100",
		Aliases: RouteAliases,
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {

			return RunDeleteRoute(
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

type DeleteRouteOptions struct {
	Prefix netip.Prefix
	VNI    uint32
}

func (o *DeleteRouteOptions) AddFlags(fs *pflag.FlagSet) {
	flag.PrefixVar(fs, &o.Prefix, "prefix", o.Prefix, "Prefix of the route.")
	fs.Uint32Var(&o.VNI, "vni", o.VNI, "VNI of the route.")
}

func (o *DeleteRouteOptions) MarkRequiredFlags(cmd *cobra.Command) error {
	for _, name := range []string{"prefix", "vni"} {
		if err := cmd.MarkFlagRequired(name); err != nil {
			return err
		}
	}
	return nil
}

func RunDeleteRoute(ctx context.Context, dpdkClientFactory DPDKClientFactory, rendererFactory RendererFactory, opts DeleteRouteOptions) error {
	client, cleanup, err := dpdkClientFactory.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("error creating dpdk client: %w", err)
	}
	defer DpdkClose(cleanup)

	route, err := client.DeleteRoute(ctx, opts.VNI, &opts.Prefix)
	if err != nil && route.Status.Code == 0 {
		return fmt.Errorf("error deleting route: %w", err)
	}

	return rendererFactory.RenderObject("deleted", os.Stdout, route)
}
