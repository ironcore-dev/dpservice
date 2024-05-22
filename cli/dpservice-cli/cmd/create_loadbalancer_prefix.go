// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"fmt"
	"net/netip"
	"os"

	"github.com/ironcore-dev/dpservice-cli/flag"
	"github.com/ironcore-dev/dpservice-cli/util"
	"github.com/ironcore-dev/dpservice-go/api"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func CreateLoadBalancerPrefix(
	dpdkClientFactory DPDKClientFactory,
	rendererFactory RendererFactory,
) *cobra.Command {
	var (
		opts CreateLoadBalancerPrefixOptions
	)

	cmd := &cobra.Command{
		Use:     "lbprefix <--prefix> <--interface-id>",
		Short:   "Create a loadbalancer prefix",
		Example: "dpservice-cli create lbprefix --prefix=10.10.10.0/24 --interface-id=vm1",
		Args:    cobra.ExactArgs(0),
		Aliases: PrefixAliases,
		RunE: func(cmd *cobra.Command, args []string) error {

			return RunCreateLoadBalancerPrefix(
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

type CreateLoadBalancerPrefixOptions struct {
	Prefix      netip.Prefix
	InterfaceID string
}

func (o *CreateLoadBalancerPrefixOptions) AddFlags(fs *pflag.FlagSet) {
	flag.PrefixVar(fs, &o.Prefix, "prefix", o.Prefix, "Prefix to add to the interface.")
	fs.StringVar(&o.InterfaceID, "interface-id", o.InterfaceID, "ID of the interface to create the prefix for.")
}

func (o *CreateLoadBalancerPrefixOptions) MarkRequiredFlags(cmd *cobra.Command) error {
	for _, name := range []string{"prefix", "interface-id"} {
		if err := cmd.MarkFlagRequired(name); err != nil {
			return err
		}
	}
	return nil
}

func RunCreateLoadBalancerPrefix(
	ctx context.Context,
	dpdkClientFactory DPDKClientFactory,
	rendererFactory RendererFactory,
	opts CreateLoadBalancerPrefixOptions,
) error {
	client, cleanup, err := dpdkClientFactory.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("error creating dpdk client: %w", err)
	}
	defer DpdkClose(cleanup)

	lbprefix, err := client.CreateLoadBalancerPrefix(ctx, &api.LoadBalancerPrefix{
		LoadBalancerPrefixMeta: api.LoadBalancerPrefixMeta{
			InterfaceID: opts.InterfaceID,
		},
		Spec: api.LoadBalancerPrefixSpec{
			Prefix: opts.Prefix,
		},
	})
	if err != nil && lbprefix.Status.Code == 0 {
		return fmt.Errorf("error creating loadbalancer prefix: %w", err)
	}

	return rendererFactory.RenderObject(fmt.Sprintf("created, underlay route: %s", lbprefix.Spec.UnderlayRoute), os.Stdout, lbprefix)
}
