// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/ironcore-dev/dpservice-cli/util"
	"github.com/ironcore-dev/dpservice-go/api"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func GetVersion(dpdkClientFactory DPDKClientFactory, rendererFactory RendererFactory) *cobra.Command {
	var (
		opts GetVersionOptions
	)

	cmd := &cobra.Command{
		Use:     "version",
		Short:   "Get version of dpservice and protobuf.",
		Example: "dpservice-cli get version",
		Aliases: NatAliases,
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {

			return RunGetVersion(
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

type GetVersionOptions struct {
}

func (o *GetVersionOptions) AddFlags(fs *pflag.FlagSet) {
}

func (o *GetVersionOptions) MarkRequiredFlags(cmd *cobra.Command) error {
	return nil
}

func RunGetVersion(
	ctx context.Context,
	dpdkClientFactory DPDKClientFactory,
	rendererFactory RendererFactory,
	opts GetVersionOptions,
) error {
	client, cleanup, err := dpdkClientFactory.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("error creating dpdk client: %w", err)
	}
	defer DpdkClose(cleanup)

	svcVersion, err := client.GetVersion(ctx, &api.Version{
		TypeMeta: api.TypeMeta{Kind: api.VersionKind},
		VersionMeta: api.VersionMeta{
			ClientName:    "dpservice-cli",
			ClientVersion: util.BuildVersion,
		},
	})
	if err != nil && svcVersion.Status.Code == 0 {
		return fmt.Errorf("error getting version: %w", err)
	}
	return rendererFactory.RenderObject("", os.Stdout, svcVersion)
}
