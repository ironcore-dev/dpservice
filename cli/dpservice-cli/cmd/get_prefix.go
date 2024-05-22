// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"github.com/ironcore-dev/dpservice-cli/util"
	"github.com/spf13/cobra"
)

func GetPrefix(dpdkClientFactory DPDKClientFactory, rendererFactory RendererFactory) *cobra.Command {
	var (
		opts ListPrefixesOptions
	)

	cmd := &cobra.Command{
		Use:     "prefix <--interface-id>",
		Short:   "List prefix(es) on interface.",
		Example: "dpservice-cli get prefix --interface-id=vm1",
		Args:    cobra.ExactArgs(0),
		Aliases: PrefixAliases,
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunListPrefixes(
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
