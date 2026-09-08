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

func EncryptionDisable(dpdkClientFactory DPDKClientFactory, rendererFactory RendererFactory) *cobra.Command {
	var (
		opts EncryptionDisableOptions
	)

	cmd := &cobra.Command{
		Use:     "disable <--interface-id>",
		Short:   "Disable encryption on an interface",
		Example: "dpservice-cli encryption disable --interface-id=vm1",
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {

			return RunEncryptionDisable(
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

type EncryptionDisableOptions struct {
	InterfaceID string
}

func (o *EncryptionDisableOptions) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&o.InterfaceID, "interface-id", o.InterfaceID, "ID of the interface.")
}

func (o *EncryptionDisableOptions) MarkRequiredFlags(cmd *cobra.Command) error {
	for _, name := range []string{"interface-id"} {
		if err := cmd.MarkFlagRequired(name); err != nil {
			return err
		}
	}
	return nil
}

func RunEncryptionDisable(
	ctx context.Context,
	dpdkClientFactory DPDKClientFactory,
	rendererFactory RendererFactory,
	opts EncryptionDisableOptions,
) error {
	client, cleanup, err := dpdkClientFactory.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("error creating dpdk client: %w", err)
	}
	defer DpdkClose(cleanup)

	encryption, err := client.DisableInterfaceEncryption(ctx, opts.InterfaceID)
	if err != nil {
		return fmt.Errorf("error disabling interface encryption: %w", err)
	}

	return rendererFactory.RenderObject("disabled", os.Stdout, encryption)
}
