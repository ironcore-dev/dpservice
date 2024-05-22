// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

func Reset(factory DPDKClientFactory) *cobra.Command {
	rendererOptions := &RendererOptions{Output: "name"}

	cmd := &cobra.Command{
		Use:  "reset [command]",
		Args: cobra.NoArgs,
		RunE: SubcommandRequired,
	}

	rendererOptions.AddFlags(cmd.PersistentFlags())

	subcommands := []*cobra.Command{
		ResetVni(factory, rendererOptions),
	}

	cmd.Short = fmt.Sprintf("Resets one of %v", CommandNames(subcommands))
	cmd.Long = fmt.Sprintf("Resets one of %v", CommandNames(subcommands))

	cmd.AddCommand(
		subcommands...,
	)

	return cmd
}
