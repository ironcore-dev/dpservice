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
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func GetSecurityAssociation(dpdkClientFactory DPDKClientFactory, rendererFactory RendererFactory) *cobra.Command {
	var (
		opts GetSecurityAssociationOptions
	)

	cmd := &cobra.Command{
		Use:     "securityassociation <--spi> <--src-underlay> <--dst-underlay>",
		Short:   "Get an IPsec Security Association",
		Example: "dpservice-cli get securityassociation --spi=100 --src-underlay=fc00:1:: --dst-underlay=fc00:2::",
		Aliases: SecurityAssociationAliases,
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {

			return RunGetSecurityAssociation(
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

type GetSecurityAssociationOptions struct {
	Spi         uint32
	SrcUnderlay netip.Addr
	DstUnderlay netip.Addr
}

func (o *GetSecurityAssociationOptions) AddFlags(fs *pflag.FlagSet) {
	fs.Uint32Var(&o.Spi, "spi", o.Spi, "Security Parameter Index of the association.")
	flag.AddrVar(fs, &o.SrcUnderlay, "src-underlay", o.SrcUnderlay, "Source underlay address of the association.")
	flag.AddrVar(fs, &o.DstUnderlay, "dst-underlay", o.DstUnderlay, "Destination underlay address of the association.")
}

func (o *GetSecurityAssociationOptions) MarkRequiredFlags(cmd *cobra.Command) error {
	for _, name := range []string{"spi", "src-underlay", "dst-underlay"} {
		if err := cmd.MarkFlagRequired(name); err != nil {
			return err
		}
	}
	return nil
}

func RunGetSecurityAssociation(
	ctx context.Context,
	dpdkClientFactory DPDKClientFactory,
	rendererFactory RendererFactory,
	opts GetSecurityAssociationOptions,
) error {
	client, cleanup, err := dpdkClientFactory.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("error creating dpdk client: %w", err)
	}
	defer DpdkClose(cleanup)

	sa, err := client.GetSecurityAssociation(ctx, opts.Spi, &opts.SrcUnderlay, &opts.DstUnderlay)
	if err != nil {
		return fmt.Errorf("error getting security association: %w", err)
	}

	return rendererFactory.RenderObject("", os.Stdout, sa)
}
