// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/ironcore-dev/dpservice-cli/util"
	"github.com/ironcore-dev/dpservice-go/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func ResetVni(dpdkClientFactory DPDKClientFactory, rendererFactory RendererFactory) *cobra.Command {
	var (
		opts ResetVniOptions
	)

	cmd := &cobra.Command{
		Use:     "vni <--vni> <--vni-type>",
		Short:   "Reset vni usage information",
		Example: "dpservice-cli reset vni --vni=vm1 --vni-type=0",
		Aliases: NatAliases,
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {

			return RunResetVni(
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

type ResetVniOptions struct {
	VNI     uint32
	VniType string
}

func (o *ResetVniOptions) AddFlags(fs *pflag.FlagSet) {
	fs.Uint32Var(&o.VNI, "vni", o.VNI, "VNI to check.")
	fs.StringVar(&o.VniType, "vni-type", "both", "VNI Type: ipv4 = 0/ipv6 = 1/both = 2.")
}

func (o *ResetVniOptions) MarkRequiredFlags(cmd *cobra.Command) error {
	for _, name := range []string{"vni"} {
		if err := cmd.MarkFlagRequired(name); err != nil {
			return err
		}
	}
	return nil
}

func RunResetVni(
	ctx context.Context,
	dpdkClientFactory DPDKClientFactory,
	rendererFactory RendererFactory,
	opts ResetVniOptions,
) error {
	client, cleanup, err := dpdkClientFactory.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("error creating dpdk client: %w", err)
	}
	defer DpdkClose(cleanup)

	var vniType uint8
	switch strings.ToLower(opts.VniType) {
	case "ipv4", "0":
		vniType = 0
	case "ipv6", "1":
		vniType = 1
	case "both", "2":
		vniType = 2
	default:
		return fmt.Errorf("VNI type can be only: ipv4 = 0/ipv6 = 1/both = 2")
	}

	vni, err := client.ResetVni(ctx, opts.VNI, vniType)
	if err != nil && !strings.Contains(err.Error(), errors.StatusErrorString) {
		return fmt.Errorf("error resetting vni: %w", err)
	}

	return rendererFactory.RenderObject("reset", os.Stdout, vni)
}
