// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/ironcore-dev/dpservice-cli/util"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func DeleteVirtualIP(dpdkClientFactory DPDKClientFactory, rendererFactory RendererFactory) *cobra.Command {
	var (
		opts DeleteVirtualIPOptions
	)

	cmd := &cobra.Command{
		Use:     "virtualip <--interface-id>",
		Short:   "Delete virtual IP from interface",
		Example: "dpservice-cli delete virtualip --interface-id=vm1",
		Aliases: VirtualIPAliases,
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {

			return RunDeleteVirtualIP(
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

type DeleteVirtualIPOptions struct {
	InterfaceID string
}

func (o *DeleteVirtualIPOptions) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&o.InterfaceID, "interface-id", o.InterfaceID, "Interface ID of the Virtual IP.")
}

func (o *DeleteVirtualIPOptions) MarkRequiredFlags(cmd *cobra.Command) error {
	for _, name := range []string{"interface-id"} {
		if err := cmd.MarkFlagRequired(name); err != nil {
			return err
		}
	}
	return nil
}

func RunDeleteVirtualIP(ctx context.Context, dpdkClientFactory DPDKClientFactory, rendererFactory RendererFactory, opts DeleteVirtualIPOptions) error {
	client, cleanup, err := dpdkClientFactory.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("error creating dpdk client: %w", err)
	}
	defer DpdkClose(cleanup)

	virtualIP, err := client.DeleteVirtualIP(ctx, opts.InterfaceID)
	if err != nil && virtualIP.Status.Code == 0 {
		return fmt.Errorf("error deleting virtual ip: %w", err)
	}

	return rendererFactory.RenderObject("deleted", os.Stdout, virtualIP)
}
