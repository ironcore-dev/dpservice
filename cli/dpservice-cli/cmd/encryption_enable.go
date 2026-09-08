// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/ironcore-dev/dpservice/cli/dpservice-cli/util"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func EncryptionEnable(dpdkClientFactory DPDKClientFactory, rendererFactory RendererFactory) *cobra.Command {
	var (
		opts EncryptionEnableOptions
	)

	cmd := &cobra.Command{
		Use:     "enable <--interface-id>",
		Short:   "Enable encryption on an interface",
		Example: "dpservice-cli encryption enable --interface-id=vm1",
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {

			return RunEncryptionEnable(
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

type EncryptionEnableOptions struct {
	InterfaceID string
}

func (o *EncryptionEnableOptions) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&o.InterfaceID, "interface-id", o.InterfaceID, "ID of the interface.")
}

func (o *EncryptionEnableOptions) MarkRequiredFlags(cmd *cobra.Command) error {
	for _, name := range []string{"interface-id"} {
		if err := cmd.MarkFlagRequired(name); err != nil {
			return err
		}
	}
	return nil
}

func RunEncryptionEnable(
	ctx context.Context,
	dpdkClientFactory DPDKClientFactory,
	rendererFactory RendererFactory,
	opts EncryptionEnableOptions,
) error {
	client, cleanup, err := dpdkClientFactory.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("error creating dpdk client: %w", err)
	}
	defer DpdkClose(cleanup)

	encryption, err := client.EnableInterfaceEncryption(ctx, opts.InterfaceID)
	if err != nil {
		return fmt.Errorf("error enabling interface encryption: %w", err)
	}

	return rendererFactory.RenderObject("enabled", os.Stdout, encryption)
}
