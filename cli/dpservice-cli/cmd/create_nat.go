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

func CreateNat(dpdkClientFactory DPDKClientFactory, rendererFactory RendererFactory) *cobra.Command {
	var (
		opts CreateNatOptions
	)

	cmd := &cobra.Command{
		Use:     "nat <--interface-id> <--nat-ip> <--minport> <--maxport>",
		Short:   "Create a NAT on interface",
		Example: "dpservice-cli create nat --interface-id=vm1 --nat-ip=10.20.30.40 --minport=30000 --maxport=30100",
		Aliases: NatAliases,
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {

			return RunCreateNat(
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

type CreateNatOptions struct {
	InterfaceID string
	NatIP       netip.Addr
	MinPort     uint32
	MaxPort     uint32
}

func (o *CreateNatOptions) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&o.InterfaceID, "interface-id", o.InterfaceID, "Interface ID where to create NAT.")
	fs.Uint32Var(&o.MinPort, "minport", o.MinPort, "MinPort of NAT.")
	fs.Uint32Var(&o.MaxPort, "maxport", o.MaxPort, "MaxPort of NAT.")
	flag.AddrVar(fs, &o.NatIP, "nat-ip", o.NatIP, "NAT IP to assign to the interface.")
}

func (o *CreateNatOptions) MarkRequiredFlags(cmd *cobra.Command) error {
	for _, name := range []string{"interface-id", "minport", "maxport", "nat-ip"} {
		if err := cmd.MarkFlagRequired(name); err != nil {
			return err
		}
	}
	return nil
}

func RunCreateNat(ctx context.Context, dpdkClientFactory DPDKClientFactory, rendererFactory RendererFactory, opts CreateNatOptions) error {
	client, cleanup, err := dpdkClientFactory.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("error creating dpdk client: %w", err)
	}
	defer DpdkClose(cleanup)

	nat, err := client.CreateNat(ctx, &api.Nat{
		NatMeta: api.NatMeta{
			InterfaceID: opts.InterfaceID,
		},
		Spec: api.NatSpec{
			NatIP:   &opts.NatIP,
			MinPort: opts.MinPort,
			MaxPort: opts.MaxPort,
		},
	})
	if err != nil && nat.Status.Code == 0 {
		return fmt.Errorf("error creating nat: %w", err)
	}

	return rendererFactory.RenderObject(fmt.Sprintf("created, underlay route: %s", nat.Spec.UnderlayRoute), os.Stdout, nat)
}
