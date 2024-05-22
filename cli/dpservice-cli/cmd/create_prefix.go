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

func CreatePrefix(
	dpdkClientFactory DPDKClientFactory,
	rendererFactory RendererFactory,
) *cobra.Command {
	var (
		opts CreatePrefixOptions
	)

	cmd := &cobra.Command{
		Use:     "prefix <--prefix> <--interface-id>",
		Short:   "Create a prefix on interface.",
		Example: "dpservice-cli create prefix --prefix=10.20.30.0/24 --interface-id=vm1",
		Args:    cobra.ExactArgs(0),
		Aliases: PrefixAliases,
		RunE: func(cmd *cobra.Command, args []string) error {

			return RunCreatePrefix(
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

type CreatePrefixOptions struct {
	Prefix      netip.Prefix
	InterfaceID string
}

func (o *CreatePrefixOptions) AddFlags(fs *pflag.FlagSet) {
	flag.PrefixVar(fs, &o.Prefix, "prefix", o.Prefix, "Prefix to create on the interface.")
	fs.StringVar(&o.InterfaceID, "interface-id", o.InterfaceID, "ID of the interface where to create the prefix.")
}

func (o *CreatePrefixOptions) MarkRequiredFlags(cmd *cobra.Command) error {
	for _, name := range []string{"prefix", "interface-id"} {
		if err := cmd.MarkFlagRequired(name); err != nil {
			return err
		}
	}
	return nil
}

func RunCreatePrefix(
	ctx context.Context,
	dpdkClientFactory DPDKClientFactory,
	rendererFactory RendererFactory,
	opts CreatePrefixOptions,
) error {
	client, cleanup, err := dpdkClientFactory.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("error creating dpdk client: %w", err)
	}
	defer DpdkClose(cleanup)

	prefix, err := client.CreatePrefix(ctx, &api.Prefix{
		PrefixMeta: api.PrefixMeta{
			InterfaceID: opts.InterfaceID,
		},
		Spec: api.PrefixSpec{
			Prefix: opts.Prefix,
		},
	})
	if err != nil && prefix.Status.Code == 0 {
		return fmt.Errorf("error creating prefix: %w", err)
	}

	return rendererFactory.RenderObject(fmt.Sprintf("created, underlay route: %s", prefix.Spec.UnderlayRoute), os.Stdout, prefix)
}
