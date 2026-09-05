// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// Unlike create and delete this takes no object sources: what it replaces is named by one set of
// flags and what it becomes by another, which does not fit an object read from a file.
func Update(factory DPDKClientFactory) *cobra.Command {
	rendererOptions := &RendererOptions{Output: "name"}

	cmd := &cobra.Command{
		Use:  "update [command]",
		Args: cobra.NoArgs,
		RunE: SubcommandRequired,
	}

	rendererOptions.AddFlags(cmd.PersistentFlags())

	subcommands := []*cobra.Command{
		UpdateSecurityAssociation(factory, rendererOptions),
	}

	cmd.Short = fmt.Sprintf("Updates one of %v", CommandNames(subcommands))
	cmd.Long = fmt.Sprintf("Updates one of %v", CommandNames(subcommands))

	cmd.AddCommand(subcommands...)

	return cmd
}
