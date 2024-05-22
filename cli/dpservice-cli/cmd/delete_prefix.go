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
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func DeletePrefix(dpdkClientFactory DPDKClientFactory, rendererFactory RendererFactory) *cobra.Command {
	var (
		opts DeletePrefixOptions
	)

	cmd := &cobra.Command{
		Use:     "prefix <--prefix> <--interface-id>",
		Short:   "Delete a prefix",
		Example: "dpservice-cli delete prefix --prefix=10.20.30.0/24 --interface-id=vm1",
		Aliases: PrefixAliases,
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {

			return RunDeletePrefix(
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

type DeletePrefixOptions struct {
	Prefix      netip.Prefix
	InterfaceID string
}

func (o *DeletePrefixOptions) AddFlags(fs *pflag.FlagSet) {
	flag.PrefixVar(fs, &o.Prefix, "prefix", o.Prefix, "Prefix to delete.")
	fs.StringVar(&o.InterfaceID, "interface-id", o.InterfaceID, "Interface ID of the prefix.")
}

func (o *DeletePrefixOptions) MarkRequiredFlags(cmd *cobra.Command) error {
	for _, name := range []string{"prefix", "interface-id"} {
		if err := cmd.MarkFlagRequired(name); err != nil {
			return err
		}
	}
	return nil
}

func RunDeletePrefix(ctx context.Context, dpdkClientFactory DPDKClientFactory, rendererFactory RendererFactory, opts DeletePrefixOptions) error {
	client, cleanup, err := dpdkClientFactory.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("error creating dpdk client: %w", err)
	}
	defer DpdkClose(cleanup)

	prefix, err := client.DeletePrefix(ctx, opts.InterfaceID, &opts.Prefix)
	if err != nil && prefix.Status.Code == 0 {
		return fmt.Errorf("error deleting prefix: %w", err)
	}

	return rendererFactory.RenderObject("deleted", os.Stdout, prefix)
}
