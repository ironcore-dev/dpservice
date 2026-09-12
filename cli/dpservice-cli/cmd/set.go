// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

func Set(factory DPDKClientFactory) *cobra.Command {
	rendererOptions := &RendererOptions{Output: "name"}

	cmd := &cobra.Command{
		Use:  "set [command]",
		Args: cobra.NoArgs,
		RunE: SubcommandRequired,
	}

	rendererOptions.AddFlags(cmd.PersistentFlags())

	subcommands := []*cobra.Command{
		SetFirewallParams(factory, rendererOptions),
	}

	cmd.Short = fmt.Sprintf("Sets one of %v", CommandNames(subcommands))
	cmd.Long = fmt.Sprintf("Sets one of %v", CommandNames(subcommands))

	cmd.AddCommand(
		subcommands...,
	)

	return cmd
}
