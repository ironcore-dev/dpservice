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

func GetInterface(dpdkClientFactory DPDKClientFactory, rendererFactory RendererFactory) *cobra.Command {
	var (
		opts GetInterfaceOptions
	)

	cmd := &cobra.Command{
		Use:     "interface <--id>",
		Short:   "Get interface",
		Example: "dpservice-cli get interface --id=vm1",
		Aliases: InterfaceAliases,
		RunE: func(cmd *cobra.Command, args []string) error {

			return RunGetInterface(
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

type GetInterfaceOptions struct {
	ID string
}

func (o *GetInterfaceOptions) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&o.ID, "id", o.ID, "ID of the interface.")
}

func (o *GetInterfaceOptions) MarkRequiredFlags(cmd *cobra.Command) error {
	return nil
}

func RunGetInterface(
	ctx context.Context,
	dpdkClientFactory DPDKClientFactory,
	rendererFactory RendererFactory,
	opts GetInterfaceOptions,
) error {
	client, cleanup, err := dpdkClientFactory.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("error creating dpdk client: %w", err)
	}
	defer DpdkClose(cleanup)

	if opts.ID == "" {
		return RunListInterfaces(
			ctx,
			dpdkClientFactory,
			rendererFactory,
			ListInterfacesOptions{},
		)
	} else {
		iface, err := client.GetInterface(ctx, opts.ID)
		if err != nil && iface.Status.Code == 0 {
			return fmt.Errorf("error getting interface: %w", err)
		}

		if rendererFactory.GetWide() {
			nat, err := client.GetNat(ctx, iface.ID)
			if err == nil {
				iface.Spec.Nat = nat
			}

			vip, err := client.GetVirtualIP(ctx, iface.ID)
			if err == nil {
				iface.Spec.VIP = vip
			}
		}

		return rendererFactory.RenderObject("", os.Stdout, iface)
	}
}
