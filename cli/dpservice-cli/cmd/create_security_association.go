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

func CreateSecurityAssociation(dpdkClientFactory DPDKClientFactory, rendererFactory RendererFactory) *cobra.Command {
	var (
		opts CreateSecurityAssociationOptions
	)

	cmd := &cobra.Command{
		Use:     "securityassociation <--vni> <--spi> <--direction> <--src-underlay> <--dst-underlay> <--key> <--salt>",
		Short:   "Create an IPsec Security Association",
		Example: "dpservice-cli create securityassociation --vni=100 --spi=43794 --direction=egress --src-underlay=fc00:1:: --dst-underlay=fc00:2:: --key=247b0ea251c93d6fb84017e59a2cd386 --salt=1bf460a7",
		Aliases: SecurityAssociationAliases,
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {

			return RunCreateSecurityAssociation(
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

type CreateSecurityAssociationOptions struct {
	Vni          uint32
	Spi          uint32
	Direction    string
	Algorithm    string
	SrcUnderlay  netip.Addr
	DstUnderlay  netip.Addr
	Key          string
	Salt         string
	ReplayWindow uint32
	Esn          bool
}

func (o *CreateSecurityAssociationOptions) AddFlags(fs *pflag.FlagSet) {
	fs.Uint32Var(&o.Vni, "vni", o.Vni, "VNI whose traffic this association protects.")
	fs.Uint32Var(&o.Spi, "spi", o.Spi, "Security Parameter Index, as carried in the ESP header.")
	fs.StringVar(&o.Direction, "direction", o.Direction, "Direction of the association (ingress or egress).")
	fs.StringVar(&o.Algorithm, "algorithm", "aes-128-gcm", "Cipher to use (aes-128-gcm or aes-256-gcm).")
	flag.AddrVar(fs, &o.SrcUnderlay, "src-underlay", o.SrcUnderlay, "Source underlay address, matched on its first 64 bits.")
	flag.AddrVar(fs, &o.DstUnderlay, "dst-underlay", o.DstUnderlay, "Destination underlay address, matched on its first 64 bits.")
	fs.StringVar(&o.Key, "key", o.Key, "Hex-encoded cipher key.")
	fs.StringVar(&o.Salt, "salt", o.Salt, "Hex-encoded salt, the implicit part of the nonce.")
	// Deliberately unvalidated here: which values a direction allows is dpservice's to decide,
	// and a check in this process would hide that answer behind a client-side failure.
	fs.Uint32Var(&o.ReplayWindow, "replay-window", o.ReplayWindow, "Anti-replay window in packets, ingress only. Zero, the default, disables replay checking.")
	// Not validated here either, and for a second reason on top of the one above: the two ends of
	// a tunnel have to agree on this, and only whoever configures both can know that they do.
	fs.BoolVar(&o.Esn, "esn", o.Esn, "Use extended (64-bit) sequence numbers. Both ends of the tunnel must be created with the same value.")
}

func (o *CreateSecurityAssociationOptions) MarkRequiredFlags(cmd *cobra.Command) error {
	for _, name := range []string{"vni", "spi", "direction", "src-underlay", "dst-underlay", "key", "salt"} {
		if err := cmd.MarkFlagRequired(name); err != nil {
			return err
		}
	}
	return nil
}

func RunCreateSecurityAssociation(
	ctx context.Context,
	dpdkClientFactory DPDKClientFactory,
	rendererFactory RendererFactory,
	opts CreateSecurityAssociationOptions,
) error {
	client, cleanup, err := dpdkClientFactory.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("error creating dpdk client: %w", err)
	}
	defer DpdkClose(cleanup)

	sa, err := client.CreateSecurityAssociation(ctx, &api.SecurityAssociation{
		TypeMeta: api.TypeMeta{Kind: api.SecurityAssociationKind},
		SecurityAssociationMeta: api.SecurityAssociationMeta{
			Vni:         opts.Vni,
			Spi:         opts.Spi,
			Direction:   opts.Direction,
			SrcUnderlay: &opts.SrcUnderlay,
			DstUnderlay: &opts.DstUnderlay,
		},
		Spec: api.SecurityAssociationSpec{
			Algorithm:    opts.Algorithm,
			Key:          opts.Key,
			Salt:         opts.Salt,
			ReplayWindow: opts.ReplayWindow,
			Esn:          opts.Esn,
		},
	})
	if err != nil {
		return fmt.Errorf("error creating security association: %w", err)
	}

	return rendererFactory.RenderObject(fmt.Sprintf("created, vni: %d, spi: %d", sa.Vni, sa.Spi), os.Stdout, sa)
}
