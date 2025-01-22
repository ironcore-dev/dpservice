// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/ironcore-dev/dpservice/cli/dpservice-cli/util"
	"github.com/ironcore-dev/dpservice/go/dpservice-go/api"
	"github.com/ironcore-dev/dpservice/go/dpservice-go/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func GetVirtualIP(dpdkClientFactory DPDKClientFactory, rendererFactory RendererFactory) *cobra.Command {
	var (
		opts GetVirtualIPOptions
	)

	cmd := &cobra.Command{
		Use:     "virtualip <--interface-id>",
		Short:   "Get Virtual IP on interface",
		Example: "dpservice-cli get virtualip --interface-id=vm1",
		Aliases: VirtualIPAliases,
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {

			return RunGetVirtualIP(
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

type GetVirtualIPOptions struct {
	InterfaceID string
}

func (o *GetVirtualIPOptions) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&o.InterfaceID, "interface-id", o.InterfaceID, "Interface ID of the Virtual IP.")
}

func (o *GetVirtualIPOptions) MarkRequiredFlags(cmd *cobra.Command) error {
	return nil
}

func RunGetVirtualIP(
	ctx context.Context,
	dpdkClientFactory DPDKClientFactory,
	rendererFactory RendererFactory,
	opts GetVirtualIPOptions,
) error {
	client, cleanup, err := dpdkClientFactory.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("error creating dpdk client: %w", err)
	}
	defer DpdkClose(cleanup)

	if opts.InterfaceID == "" {
		ifaces, err := client.ListInterfaces(ctx)
		if err != nil {
			return fmt.Errorf("error listing interfaces: %w", err)
		}
		if len(ifaces.Items) == 0 {
			return fmt.Errorf("error getting virtual ip: [error code %d] NO_VM", errors.NO_VM)
		}

		virtualIPs := make([]*api.VirtualIP, 0, len(ifaces.Items))
		for _, iface := range ifaces.Items {
			vip, err := client.GetVirtualIP(ctx, iface.ID, errors.Ignore(errors.SNAT_NO_DATA))
			if err != nil {
				return fmt.Errorf("error getting virtual ip: %w", err)
			}
			if vip.Status.Code == 0 {
				virtualIPs = append(virtualIPs, vip)
			}
		}
		for _, vip := range virtualIPs {
			err = rendererFactory.RenderObject("", os.Stdout, vip)
			if err != nil {
				return err
			}
		}
		return nil
	}

	virtualIP, err := client.GetVirtualIP(ctx, opts.InterfaceID)
	if err != nil {
		return fmt.Errorf("error getting virtual ip: %w", err)
	}

	return rendererFactory.RenderObject("", os.Stdout, virtualIP)
}
