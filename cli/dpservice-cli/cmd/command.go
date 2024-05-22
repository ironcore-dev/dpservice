// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"github.com/ironcore-dev/dpservice-cli/util"
	"github.com/spf13/cobra"
)

func Command() *cobra.Command {
	dpdkClientOptions := &DPDKClientOptions{}
	rendererOptions := &RendererOptions{}

	cmd := &cobra.Command{
		Use:           "dpservice-cli [command]",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE:          SubcommandRequired,
		Version:       util.BuildVersion,
	}

	rendererOptions.AddFlags(cmd.PersistentFlags())
	dpdkClientOptions.AddFlags(cmd.PersistentFlags())

	cmd.AddCommand(
		Create(dpdkClientOptions),
		Get(dpdkClientOptions),
		List(dpdkClientOptions),
		Delete(dpdkClientOptions),
		Reset(dpdkClientOptions),
		Init(dpdkClientOptions, rendererOptions),
		Capture(dpdkClientOptions),
		completionCmd,
	)

	return cmd
}
