// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/ironcore-dev/dpservice-cli/util"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func ListInterfaces(dpdkClientFactory DPDKClientFactory, rendererFactory RendererFactory) *cobra.Command {
	var (
		opts ListInterfacesOptions
	)

	cmd := &cobra.Command{
		Use:     "interfaces",
		Short:   "List all interfaces",
		Example: "dpservice-cli list interfaces",
		Aliases: InterfaceAliases,
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunListInterfaces(
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

type ListInterfacesOptions struct {
	SortBy string
}

func (o *ListInterfacesOptions) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&o.SortBy, "sort-by", "", "Column to sort by.")
}

func (o *ListInterfacesOptions) MarkRequiredFlags(cmd *cobra.Command) error {
	return nil
}

func RunListInterfaces(
	ctx context.Context,
	dpdkClientFactory DPDKClientFactory,
	rendererFactory RendererFactory,
	opts ListInterfacesOptions,
) error {
	client, cleanup, err := dpdkClientFactory.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("error getting dpdk client: %w", err)
	}
	defer DpdkClose(cleanup)

	interfaceList, err := client.ListInterfaces(ctx)
	if err != nil {
		return fmt.Errorf("error listing interfaces: %w", err)
	}

	if rendererFactory.GetWide() {
		for i, iface := range interfaceList.Items {
			nat, err := client.GetNat(ctx, iface.ID)
			if err == nil {
				interfaceList.Items[i].Spec.Nat = nat
			}
		}
		for i, iface := range interfaceList.Items {
			vip, err := client.GetVirtualIP(ctx, iface.ID)
			if err == nil {
				interfaceList.Items[i].Spec.VIP = vip
			}
		}
	}
	// sort items in list
	interfaces := interfaceList.Items
	sort.SliceStable(interfaces, func(i, j int) bool {
		mi, mj := interfaces[i], interfaces[j]
		switch strings.ToLower(opts.SortBy) {
		case "vni":
			if mi.Spec.VNI != mj.Spec.VNI {
				return mi.Spec.VNI < mj.Spec.VNI
			}
			return mi.Spec.IPv4.String() < mj.Spec.IPv4.String()
		case "device":
			return mi.Spec.Device < mj.Spec.Device
		case "ipv4":
			if mi.Spec.IPv4.String() != mj.Spec.IPv4.String() {
				return mi.Spec.IPv4.String() < mj.Spec.IPv4.String()
			}
			return mi.Spec.VNI < mj.Spec.VNI
		case "ipv6":
			return mi.Spec.IPv6.String() < mj.Spec.IPv6.String()
		case "underlayroute":
			return mi.Spec.UnderlayRoute.String() < mj.Spec.UnderlayRoute.String()
		default:
			return mi.ID < mj.ID
		}
	})
	interfaceList.Items = interfaces

	return rendererFactory.RenderList("", os.Stdout, interfaceList)
}
