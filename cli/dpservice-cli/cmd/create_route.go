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
	"github.com/ironcore-dev/dpservice-go/api"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func CreateRoute(dpdkClientFactory DPDKClientFactory, rendererFactory RendererFactory) *cobra.Command {
	var (
		opts CreateRouteOptions
	)

	cmd := &cobra.Command{
		Use:     "route <--prefix> <--next-hop-vni> <--next-hop-ip> <--vni>",
		Short:   "Create a route",
		Example: "dpservice-cli create route --prefix=10.100.3.0/24 --next-hop-vni=0 --next-hop-ip=fc00:2::64:0:1 --vni=100",
		Aliases: RouteAliases,
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {

			return RunCreateRoute(
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

type CreateRouteOptions struct {
	Prefix     netip.Prefix
	NextHopVNI uint32
	NextHopIP  netip.Addr
	VNI        uint32
}

func (o *CreateRouteOptions) AddFlags(fs *pflag.FlagSet) {
	flag.PrefixVar(fs, &o.Prefix, "prefix", o.Prefix, "Prefix for the route.")
	fs.Uint32Var(&o.NextHopVNI, "next-hop-vni", o.NextHopVNI, "Next hop VNI for the route.")
	flag.AddrVar(fs, &o.NextHopIP, "next-hop-ip", o.NextHopIP, "Next hop IP for the route.")
	fs.Uint32Var(&o.VNI, "vni", o.VNI, "Source VNI for the route.")
}

func (o *CreateRouteOptions) MarkRequiredFlags(cmd *cobra.Command) error {
	for _, name := range []string{"prefix", "next-hop-vni", "next-hop-ip", "vni"} {
		if err := cmd.MarkFlagRequired(name); err != nil {
			return err
		}
	}
	return nil
}

func RunCreateRoute(
	ctx context.Context,
	dpdkClientFactory DPDKClientFactory,
	rendererFactory RendererFactory,
	opts CreateRouteOptions,
) error {
	client, cleanup, err := dpdkClientFactory.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("error creating dpdk client: %w", err)
	}
	defer DpdkClose(cleanup)

	route, err := client.CreateRoute(ctx, &api.Route{
		RouteMeta: api.RouteMeta{
			VNI: opts.VNI,
		},
		Spec: api.RouteSpec{Prefix: &opts.Prefix,
			NextHop: &api.RouteNextHop{
				VNI: opts.NextHopVNI,
				IP:  &opts.NextHopIP,
			}},
	})
	if err != nil && route.Status.Code == 0 {
		return fmt.Errorf("error creating route: %w", err)
	}

	return rendererFactory.RenderObject(fmt.Sprintf("created, Next Hop IP: %s", opts.NextHopIP), os.Stdout, route)
}
