// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/ironcore-dev/dpservice-cli/util"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func DeleteLoadBalancer(dpdkClientFactory DPDKClientFactory, rendererFactory RendererFactory) *cobra.Command {
	var (
		opts DeleteLoadBalancerOptions
	)

	cmd := &cobra.Command{
		Use:     "loadbalancer <--id>",
		Short:   "Delete loadbalancer",
		Example: "dpservice-cli delete loadbalancer --id=1",
		Aliases: LoadBalancerAliases,
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {

			return RunDeleteLoadBalancer(
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

type DeleteLoadBalancerOptions struct {
	ID string
}

func (o *DeleteLoadBalancerOptions) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&o.ID, "id", o.ID, "LoadBalancer ID to delete.")
}

func (o *DeleteLoadBalancerOptions) MarkRequiredFlags(cmd *cobra.Command) error {
	for _, name := range []string{"id"} {
		if err := cmd.MarkFlagRequired(name); err != nil {
			return err
		}
	}
	return nil
}

func RunDeleteLoadBalancer(ctx context.Context, dpdkClientFactory DPDKClientFactory, rendererFactory RendererFactory, opts DeleteLoadBalancerOptions) error {
	client, cleanup, err := dpdkClientFactory.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("error creating dpdk client: %w", err)
	}
	defer DpdkClose(cleanup)

	lb, err := client.DeleteLoadBalancer(ctx, opts.ID)
	if err != nil && lb.Status.Code == 0 {
		return fmt.Errorf("error deleting loadbalancer: %w", err)
	}

	return rendererFactory.RenderObject("deleted", os.Stdout, lb)
}
