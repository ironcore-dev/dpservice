// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strings"

	"github.com/ironcore-dev/dpservice-cli/flag"
	"github.com/ironcore-dev/dpservice-cli/util"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func ListNats(dpdkClientFactory DPDKClientFactory, rendererFactory RendererFactory) *cobra.Command {
	var (
		opts ListNatsOptions
	)

	cmd := &cobra.Command{
		Use:     "nats <--nat-ip> <--nat-type>",
		Short:   "List local/neighbor/both nats with selected IP",
		Example: "dpservice-cli list nats --nat-ip=10.20.30.40 --info-type=local",
		Aliases: NatAliases,
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {

			return RunListNats(
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

type ListNatsOptions struct {
	NatIP   netip.Addr
	NatType string
	SortBy  string
}

func (o *ListNatsOptions) AddFlags(fs *pflag.FlagSet) {
	flag.AddrVar(fs, &o.NatIP, "nat-ip", o.NatIP, "NAT IP to get info for")
	fs.StringVar(&o.NatType, "nat-type", "0", "NAT type: Any = 0/Local = 1/Neigh(bor) = 2")
	fs.StringVar(&o.SortBy, "sort-by", "", "Column to sort by.")
}

func (o *ListNatsOptions) MarkRequiredFlags(cmd *cobra.Command) error {
	for _, name := range []string{"nat-ip"} {
		if err := cmd.MarkFlagRequired(name); err != nil {
			return err
		}
	}
	return nil
}

func RunListNats(
	ctx context.Context,
	dpdkClientFactory DPDKClientFactory,
	rendererFactory RendererFactory,
	opts ListNatsOptions,
) error {
	client, cleanup, err := dpdkClientFactory.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("error creating dpdk client: %w", err)
	}
	defer DpdkClose(cleanup)

	natList, err := client.ListNats(ctx, &opts.NatIP, opts.NatType)
	if err != nil {
		return fmt.Errorf("error listing nats: %w", err)
	}

	// sort items in list
	nats := natList.Items
	sort.SliceStable(nats, func(i, j int) bool {
		mi, mj := nats[i], nats[j]
		switch strings.ToLower(opts.SortBy) {
		case "ip":
			if mi.Spec.NatIP != nil && mj.Spec.NatIP != nil {
				return mi.Spec.NatIP.String() < mj.Spec.NatIP.String()
			}
			return true
		case "minport":
			return mi.Spec.MinPort < mj.Spec.MinPort
		case "maxport":
			return mi.Spec.MaxPort < mj.Spec.MaxPort
		case "underlayroute":
			if mi.Spec.UnderlayRoute != nil && mj.Spec.UnderlayRoute != nil {
				return mi.Spec.UnderlayRoute.String() < mj.Spec.UnderlayRoute.String()
			}
			return true
		default:
			return mi.Spec.Vni < mj.Spec.Vni
		}
	})
	natList.Items = nats

	return rendererFactory.RenderList("", os.Stdout, natList)
}
