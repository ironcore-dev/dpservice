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

func CreateVirtualIP(dpdkClientFactory DPDKClientFactory, rendererFactory RendererFactory) *cobra.Command {
	var (
		opts CreateVirtualIPOptions
	)

	cmd := &cobra.Command{
		Use:     "virtualip <--vip> <--interface-id>",
		Short:   "Create a virtual IP on interface.",
		Example: "dpservice-cli create virtualip --vip=20.20.20.20 --interface-id=vm1",
		Aliases: VirtualIPAliases,
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {

			return RunCreateVirtualIP(
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

type CreateVirtualIPOptions struct {
	Vip         netip.Addr
	InterfaceID string
}

func (o *CreateVirtualIPOptions) AddFlags(fs *pflag.FlagSet) {
	flag.AddrVar(fs, &o.Vip, "vip", o.Vip, "Virtual IP to create on interface.")
	fs.StringVar(&o.InterfaceID, "interface-id", o.InterfaceID, "Interface ID where to create the virtual IP.")
}

func (o *CreateVirtualIPOptions) MarkRequiredFlags(cmd *cobra.Command) error {
	for _, name := range []string{"vip", "interface-id"} {
		if err := cmd.MarkFlagRequired(name); err != nil {
			return err
		}
	}
	return nil
}

func RunCreateVirtualIP(
	ctx context.Context,
	dpdkClientFactory DPDKClientFactory,
	rendererFactory RendererFactory,
	opts CreateVirtualIPOptions,
) error {
	client, cleanup, err := dpdkClientFactory.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("error creating dpdk client: %w", err)
	}
	defer DpdkClose(cleanup)

	virtualIP, err := client.CreateVirtualIP(ctx, &api.VirtualIP{
		VirtualIPMeta: api.VirtualIPMeta{
			InterfaceID: opts.InterfaceID,
		},
		Spec: api.VirtualIPSpec{
			IP: &opts.Vip,
		},
	})
	if err != nil && virtualIP.Status.Code == 0 {
		return fmt.Errorf("error creating virtual ip: %w", err)
	}

	return rendererFactory.RenderObject(fmt.Sprintf("created, underlay route: %s", virtualIP.Spec.UnderlayRoute), os.Stdout, virtualIP)
}
