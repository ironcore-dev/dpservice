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

func GetLoadBalancer(dpdkClientFactory DPDKClientFactory, rendererFactory RendererFactory) *cobra.Command {
	var (
		opts GetLoadBalancerOptions
	)

	cmd := &cobra.Command{
		Use:     "loadbalancer <--id>",
		Short:   "Get loadbalancer",
		Example: "dpservice-cli get loadbalancer --id=4",
		Aliases: LoadBalancerAliases,
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {

			return RunGetLoadBalancer(
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

type GetLoadBalancerOptions struct {
	ID string
}

func (o *GetLoadBalancerOptions) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&o.ID, "id", o.ID, "ID of the LoadBalancer.")
}

func (o *GetLoadBalancerOptions) MarkRequiredFlags(cmd *cobra.Command) error {
	for _, name := range []string{"id"} {
		if err := cmd.MarkFlagRequired(name); err != nil {
			return err
		}
	}
	return nil
}

func RunGetLoadBalancer(
	ctx context.Context,
	dpdkClientFactory DPDKClientFactory,
	rendererFactory RendererFactory,
	opts GetLoadBalancerOptions,
) error {
	client, cleanup, err := dpdkClientFactory.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("error creating dpdk client: %w", err)
	}
	defer DpdkClose(cleanup)

	lb, err := client.GetLoadBalancer(ctx, opts.ID)
	if err != nil && lb.Status.Code == 0 {
		return fmt.Errorf("error getting loadbalancer: %w", err)
	}

	return rendererFactory.RenderObject("", os.Stdout, lb)
}
