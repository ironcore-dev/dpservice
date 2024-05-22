// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

func Capture(factory DPDKClientFactory) *cobra.Command {
	rendererOptions := &RendererOptions{Output: "table"}

	cmd := &cobra.Command{
		Use:  "capture",
		Args: cobra.NoArgs,
		RunE: SubcommandRequired,
	}

	rendererOptions.AddFlags(cmd.PersistentFlags())

	subcommands := []*cobra.Command{
		CaptureStart(factory, rendererOptions),
		CaptureStop(factory, rendererOptions),
		CaptureStatus(factory, rendererOptions),
	}

	cmd.Short = fmt.Sprintf("Gets one of %v", CommandNames(subcommands))
	cmd.Long = fmt.Sprintf("Gets one of %v", CommandNames(subcommands))

	cmd.AddCommand(
		subcommands...,
	)

	return cmd
}
