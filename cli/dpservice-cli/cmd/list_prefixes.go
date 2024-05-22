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
	"github.com/ironcore-dev/dpservice-go/api"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func ListPrefixes(dpdkClientFactory DPDKClientFactory, rendererFactory RendererFactory) *cobra.Command {
	var (
		opts ListPrefixesOptions
	)

	cmd := &cobra.Command{
		Use:     "prefixes <--interface-id>",
		Short:   "List prefix(es) on interface.",
		Example: "dpservice-cli list prefixes --interface-id=vm1",
		Args:    cobra.ExactArgs(0),
		Aliases: PrefixAliases,
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunListPrefixes(
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

type ListPrefixesOptions struct {
	InterfaceID string
	SortBy      string
}

func (o *ListPrefixesOptions) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&o.InterfaceID, "interface-id", o.InterfaceID, "Interface ID of the prefix.")
	fs.StringVar(&o.SortBy, "sort-by", "", "Column to sort by.")
}

func (o *ListPrefixesOptions) MarkRequiredFlags(cmd *cobra.Command) error {
	return nil
}

func RunListPrefixes(
	ctx context.Context,
	factory DPDKClientFactory,
	rendererFactory RendererFactory,
	opts ListPrefixesOptions,
) error {
	client, cleanup, err := factory.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("error creating client: %w", err)
	}
	defer DpdkClose(cleanup)

	prefixList := &api.PrefixList{
		TypeMeta: api.TypeMeta{Kind: api.PrefixListKind},
	}
	if opts.InterfaceID == "" {
		ifaces, err := client.ListInterfaces(ctx)
		if err != nil && ifaces.Status.Code == 0 {
			return fmt.Errorf("error listing interfaces: %w", err)
		}

		for _, iface := range ifaces.Items {
			prefix, err := client.ListPrefixes(ctx, iface.ID)
			if err != nil && prefix.Status.Code == 0 {
				return fmt.Errorf("error getting prefixes: %w", err)
			}
			prefixList.Items = append(prefixList.Items, prefix.Items...)
		}
	} else {
		prefixList, err = client.ListPrefixes(ctx, opts.InterfaceID)
		if err != nil {
			return fmt.Errorf("error listing prefixes: %w", err)
		}
	}
	// sort items in list
	prefixes := prefixList.Items
	sort.SliceStable(prefixes, func(i, j int) bool {
		mi, mj := prefixes[i], prefixes[j]
		switch strings.ToLower(opts.SortBy) {
		case "underlayroute":
			return mi.Spec.UnderlayRoute.String() < mj.Spec.UnderlayRoute.String()
		default:
			return mi.Spec.Prefix.String() < mj.Spec.Prefix.String()
		}
	})
	prefixList.Items = prefixes

	return rendererFactory.RenderList("", os.Stdout, prefixList)
}
