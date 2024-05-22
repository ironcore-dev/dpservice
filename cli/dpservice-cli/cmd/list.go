// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

func List(factory DPDKClientFactory) *cobra.Command {
	rendererOptions := &RendererOptions{Output: "table"}

	cmd := &cobra.Command{
		Use:  "list [command]",
		Args: cobra.NoArgs,
		RunE: SubcommandRequired,
	}

	rendererOptions.AddFlags(cmd.PersistentFlags())

	subcommands := []*cobra.Command{
		ListFirewallRules(factory, rendererOptions),
		ListInterfaces(factory, rendererOptions),
		ListPrefixes(factory, rendererOptions),
		ListLoadBalancerPrefixes(factory, rendererOptions),
		ListRoutes(factory, rendererOptions),
		ListLoadBalancerTargets(factory, rendererOptions),
		ListNats(factory, rendererOptions),
	}

	cmd.Short = fmt.Sprintf("Lists one of %v", CommandNames(subcommands))
	cmd.Long = fmt.Sprintf("Lists one of %v", CommandNames(subcommands))

	cmd.AddCommand(
		subcommands...,
	)

	return cmd
}
