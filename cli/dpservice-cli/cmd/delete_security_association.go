// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"fmt"
	"net/netip"
	"os"

	"github.com/ironcore-dev/dpservice/cli/dpservice-cli/flag"
	"github.com/ironcore-dev/dpservice/cli/dpservice-cli/util"
	"github.com/ironcore-dev/dpservice/go/dpservice-go/api"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func DeleteSecurityAssociation(dpdkClientFactory DPDKClientFactory, rendererFactory RendererFactory) *cobra.Command {
	var (
		opts DeleteSecurityAssociationOptions
	)

	cmd := &cobra.Command{
		Use:     "securityassociation <--vni> <--spi> <--direction> <--src-underlay> <--dst-underlay>",
		Short:   "Delete an IPsec Security Association",
		Example: "dpservice-cli delete securityassociation --vni=100 --spi=43794 --direction=egress --src-underlay=fc00:1:: --dst-underlay=fc00:2::",
		Aliases: SecurityAssociationAliases,
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {

			return RunDeleteSecurityAssociation(
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

type DeleteSecurityAssociationOptions struct {
	Vni         uint32
	Spi         uint32
	Direction   string
	SrcUnderlay netip.Addr
	DstUnderlay netip.Addr
}

func (o *DeleteSecurityAssociationOptions) AddFlags(fs *pflag.FlagSet) {
	fs.Uint32Var(&o.Vni, "vni", o.Vni, "VNI of the association.")
	fs.Uint32Var(&o.Spi, "spi", o.Spi, "Security Parameter Index of the association.")
	fs.StringVar(&o.Direction, "direction", o.Direction, "Direction of the association (ingress or egress).")
	flag.AddrVar(fs, &o.SrcUnderlay, "src-underlay", o.SrcUnderlay, "Source underlay address of the association.")
	flag.AddrVar(fs, &o.DstUnderlay, "dst-underlay", o.DstUnderlay, "Destination underlay address of the association.")
}

func (o *DeleteSecurityAssociationOptions) MarkRequiredFlags(cmd *cobra.Command) error {
	for _, name := range []string{"vni", "spi", "direction", "src-underlay", "dst-underlay"} {
		if err := cmd.MarkFlagRequired(name); err != nil {
			return err
		}
	}
	return nil
}

func RunDeleteSecurityAssociation(
	ctx context.Context,
	dpdkClientFactory DPDKClientFactory,
	rendererFactory RendererFactory,
	opts DeleteSecurityAssociationOptions,
) error {
	client, cleanup, err := dpdkClientFactory.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("error creating dpdk client: %w", err)
	}
	defer DpdkClose(cleanup)

	sa, err := client.DeleteSecurityAssociation(ctx, &api.SecurityAssociationMeta{
		Vni:         opts.Vni,
		Spi:         opts.Spi,
		Direction:   opts.Direction,
		SrcUnderlay: &opts.SrcUnderlay,
		DstUnderlay: &opts.DstUnderlay,
	})
	if err != nil {
		return fmt.Errorf("error deleting security association: %w", err)
	}

	return rendererFactory.RenderObject(fmt.Sprintf("deleted, vni: %d, spi: %d", opts.Vni, opts.Spi), os.Stdout, sa)
}
