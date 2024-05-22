// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"github.com/ironcore-dev/dpservice-cli/util"
	"github.com/spf13/cobra"
)

func GetLoadBalancerPrefix(dpdkClientFactory DPDKClientFactory, rendererFactory RendererFactory) *cobra.Command {
	var (
		opts ListLoadBalancerPrefixesOptions
	)

	cmd := &cobra.Command{
		Use:     "lbprefix <--interface-id>",
		Short:   "List loadbalancer prefixes on interface.",
		Example: "dpservice-cli get lbprefix --interface-id=vm1",
		Aliases: LoadBalancerPrefixAliases,
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {

			return RunListLoadBalancerPrefixes(
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
