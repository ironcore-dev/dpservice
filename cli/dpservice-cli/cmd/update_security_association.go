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

func UpdateSecurityAssociation(dpdkClientFactory DPDKClientFactory, rendererFactory RendererFactory) *cobra.Command {
	var (
		opts UpdateSecurityAssociationOptions
	)

	cmd := &cobra.Command{
		Use:     "securityassociation <--vni> <--spi> <--direction> <--src-underlay> <--dst-underlay> <--new-spi> <--key> <--salt>",
		Short:   "Replace an egress IPsec Security Association, without a gap in the traffic it protects",
		Example: "dpservice-cli update securityassociation --vni=100 --spi=43794 --direction=egress --src-underlay=fc00:1:: --dst-underlay=fc00:2:: --new-spi=43795 --key=9c3d0b7e4a1f8256d0e4b39f7c15a862 --salt=5d24c9b1",
		Aliases: SecurityAssociationAliases,
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {

			return RunUpdateSecurityAssociation(
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

type UpdateSecurityAssociationOptions struct {
	Vni          uint32
	Spi          uint32
	NewSpi       uint32
	Direction    string
	Algorithm    string
	SrcUnderlay  netip.Addr
	DstUnderlay  netip.Addr
	Key          string
	Salt         string
	ReplayWindow uint32
	Esn          bool
}

func (o *UpdateSecurityAssociationOptions) AddFlags(fs *pflag.FlagSet) {
	// The first five name the association as it stands. Naming it by a SPI it no longer carries
	// replaces nothing, rather than replacing whatever took its place.
	fs.Uint32Var(&o.Vni, "vni", o.Vni, "VNI of the association.")
	fs.Uint32Var(&o.Spi, "spi", o.Spi, "Security Parameter Index the association carries now.")
	fs.StringVar(&o.Direction, "direction", o.Direction, "Direction of the association (egress, the only direction that can be replaced).")
	flag.AddrVar(fs, &o.SrcUnderlay, "src-underlay", o.SrcUnderlay, "Source underlay address of the association.")
	flag.AddrVar(fs, &o.DstUnderlay, "dst-underlay", o.DstUnderlay, "Destination underlay address of the association.")
	// Everything below is what it becomes. Nothing is carried over from what is being replaced,
	// so an omitted flag means its default rather than the value the association holds now.
	fs.Uint32Var(&o.NewSpi, "new-spi", o.NewSpi, "Security Parameter Index the association carries from here on.")
	fs.StringVar(&o.Algorithm, "algorithm", "aes-128-gcm", "Cipher to use (aes-128-gcm or aes-256-gcm).")
	fs.StringVar(&o.Key, "key", o.Key, "Hex-encoded cipher key. The replacement starts a sequence number of its own, so this has to be key material the association has not used before.")
	fs.StringVar(&o.Salt, "salt", o.Salt, "Hex-encoded salt, the implicit part of the nonce.")
	fs.Uint32Var(&o.ReplayWindow, "replay-window", o.ReplayWindow, "Anti-replay window in packets. An egress association has nothing to check, so only zero, the default, is accepted.")
	fs.BoolVar(&o.Esn, "esn", o.Esn, "Use extended (64-bit) sequence numbers. Both ends of the tunnel must agree.")
}

func (o *UpdateSecurityAssociationOptions) MarkRequiredFlags(cmd *cobra.Command) error {
	for _, name := range []string{"vni", "spi", "direction", "src-underlay", "dst-underlay", "new-spi", "key", "salt"} {
		if err := cmd.MarkFlagRequired(name); err != nil {
			return err
		}
	}
	return nil
}

func RunUpdateSecurityAssociation(
	ctx context.Context,
	dpdkClientFactory DPDKClientFactory,
	rendererFactory RendererFactory,
	opts UpdateSecurityAssociationOptions,
) error {
	client, cleanup, err := dpdkClientFactory.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("error creating dpdk client: %w", err)
	}
	defer DpdkClose(cleanup)

	sa, err := client.UpdateSecurityAssociation(ctx,
		&api.SecurityAssociationMeta{
			Vni:         opts.Vni,
			Spi:         opts.Spi,
			Direction:   opts.Direction,
			SrcUnderlay: &opts.SrcUnderlay,
			DstUnderlay: &opts.DstUnderlay,
		},
		&api.SecurityAssociationUpdate{
			NewSpi: opts.NewSpi,
			Spec: api.SecurityAssociationSpec{
				Algorithm:    opts.Algorithm,
				Key:          opts.Key,
				Salt:         opts.Salt,
				ReplayWindow: opts.ReplayWindow,
				Esn:          opts.Esn,
			},
		})
	if err != nil {
		return fmt.Errorf("error updating security association: %w", err)
	}

	return rendererFactory.RenderObject(fmt.Sprintf("updated, vni: %d, spi: %d", sa.Vni, sa.Spi), os.Stdout, sa)
}
