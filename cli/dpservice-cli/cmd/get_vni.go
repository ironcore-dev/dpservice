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

func GetVni(dpdkClientFactory DPDKClientFactory, rendererFactory RendererFactory) *cobra.Command {
	var (
		opts GetVniOptions
	)

	cmd := &cobra.Command{
		Use:     "vni <--vni> <--vni-type>",
		Short:   "Get vni usage information",
		Example: "dpservice-cli get vni --vni=vm1 --vni-type=0",
		Aliases: NatAliases,
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {

			return RunGetVni(
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

type GetVniOptions struct {
	VNI     uint32
	VniType uint8
}

func (o *GetVniOptions) AddFlags(fs *pflag.FlagSet) {
	fs.Uint32Var(&o.VNI, "vni", o.VNI, "VNI to check.")
	fs.Uint8Var(&o.VniType, "vni-type", o.VniType, "VNI Type: VniIpv4 = 0/VniIpv6 = 1.")
}

func (o *GetVniOptions) MarkRequiredFlags(cmd *cobra.Command) error {
	for _, name := range []string{"vni", "vni-type"} {
		if err := cmd.MarkFlagRequired(name); err != nil {
			return err
		}
	}
	return nil
}

func RunGetVni(
	ctx context.Context,
	dpdkClientFactory DPDKClientFactory,
	rendererFactory RendererFactory,
	opts GetVniOptions,
) error {
	client, cleanup, err := dpdkClientFactory.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("error creating dpdk client: %w", err)
	}
	defer DpdkClose(cleanup)

	vni, err := client.GetVni(ctx, opts.VNI, opts.VniType)
	if err != nil && vni.Status.Code == 0 {
		return fmt.Errorf("error getting vni: %w", err)
	}

	return rendererFactory.RenderObject("", os.Stdout, vni)
}
