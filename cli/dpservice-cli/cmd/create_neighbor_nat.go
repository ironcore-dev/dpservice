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

func CreateNeighborNat(dpdkClientFactory DPDKClientFactory, rendererFactory RendererFactory) *cobra.Command {
	var (
		opts CreateNeighborNatOptions
	)

	cmd := &cobra.Command{
		Use:     "neighbornat <--nat-ip> <--vni> <--minport> <--maxport> <--underlayroute>",
		Short:   "Create a Neighbor NAT",
		Example: "dpservice-cli create neighbornat --nat-ip=10.20.30.40 --vni=100 --minport=30000 --maxport=30100 --underlayroute=ff80::1",
		Aliases: NeighborNatAliases,
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {

			return RunCreateNeighborNat(
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

type CreateNeighborNatOptions struct {
	NatIP         netip.Addr
	Vni           uint32
	MinPort       uint32
	MaxPort       uint32
	UnderlayRoute netip.Addr
}

func (o *CreateNeighborNatOptions) AddFlags(fs *pflag.FlagSet) {
	flag.AddrVar(fs, &o.NatIP, "nat-ip", o.NatIP, "Neighbor NAT IP.")
	fs.Uint32Var(&o.Vni, "vni", o.Vni, "VNI of neighbor NAT.")
	fs.Uint32Var(&o.MinPort, "minport", o.MinPort, "MinPort of neighbor NAT.")
	fs.Uint32Var(&o.MaxPort, "maxport", o.MaxPort, "MaxPort of neighbor NAT.")
	flag.AddrVar(fs, &o.UnderlayRoute, "underlayroute", o.UnderlayRoute, "Underlay route of neighbor NAT.")
}

func (o *CreateNeighborNatOptions) MarkRequiredFlags(cmd *cobra.Command) error {
	for _, name := range []string{"nat-ip", "vni", "minport", "maxport", "underlayroute"} {
		if err := cmd.MarkFlagRequired(name); err != nil {
			return err
		}
	}
	return nil
}

func RunCreateNeighborNat(ctx context.Context, dpdkClientFactory DPDKClientFactory, rendererFactory RendererFactory, opts CreateNeighborNatOptions) error {
	client, cleanup, err := dpdkClientFactory.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("error creating dpdk client: %w", err)
	}
	defer DpdkClose(cleanup)

	neigbhorNat := &api.NeighborNat{
		TypeMeta:        api.TypeMeta{Kind: api.NeighborNatKind},
		NeighborNatMeta: api.NeighborNatMeta{NatIP: &opts.NatIP},
		Spec: api.NeighborNatSpec{
			Vni:           opts.Vni,
			MinPort:       opts.MinPort,
			MaxPort:       opts.MaxPort,
			UnderlayRoute: &opts.UnderlayRoute,
		},
	}

	nnat, err := client.CreateNeighborNat(ctx, neigbhorNat)
	if err != nil && nnat.Status.Code == 0 {
		return fmt.Errorf("error creating neighbor nat: %w", err)
	}

	return rendererFactory.RenderObject(fmt.Sprintf("created, underlay route: %s", nnat.Spec.UnderlayRoute), os.Stdout, nnat)
}
