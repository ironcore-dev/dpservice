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

func CreateLoadBalancerTarget(
	dpdkClientFactory DPDKClientFactory,
	rendererFactory RendererFactory,
) *cobra.Command {
	var (
		opts CreateLoadBalancerTargetOptions
	)

	cmd := &cobra.Command{
		Use:     "lbtarget <target-ip> <--lb-id>",
		Short:   "Create a loadbalancer target",
		Example: "dpservice-cli create lbtarget --target-ip=ff80::5 --lb-id=2",
		Args:    cobra.ExactArgs(0),
		Aliases: LoadBalancerTargetAliases,
		RunE: func(cmd *cobra.Command, args []string) error {

			return RunCreateLoadBalancerTarget(
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

type CreateLoadBalancerTargetOptions struct {
	TargetIP       netip.Addr
	LoadBalancerID string
}

func (o *CreateLoadBalancerTargetOptions) AddFlags(fs *pflag.FlagSet) {
	flag.AddrVar(fs, &o.TargetIP, "target-ip", o.TargetIP, "Loadbalancer Target IP.")
	fs.StringVar(&o.LoadBalancerID, "lb-id", o.LoadBalancerID, "ID of the loadbalancer to add the target for.")
}

func (o *CreateLoadBalancerTargetOptions) MarkRequiredFlags(cmd *cobra.Command) error {
	for _, name := range []string{"target-ip", "lb-id"} {
		if err := cmd.MarkFlagRequired(name); err != nil {
			return err
		}
	}
	return nil
}

func RunCreateLoadBalancerTarget(
	ctx context.Context,
	dpdkClientFactory DPDKClientFactory,
	rendererFactory RendererFactory,
	opts CreateLoadBalancerTargetOptions,
) error {
	client, cleanup, err := dpdkClientFactory.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("error creating dpdk client: %w", err)
	}
	defer DpdkClose(cleanup)

	lbtarget, err := client.CreateLoadBalancerTarget(ctx, &api.LoadBalancerTarget{
		TypeMeta:               api.TypeMeta{Kind: api.LoadBalancerTargetKind},
		LoadBalancerTargetMeta: api.LoadBalancerTargetMeta{LoadbalancerID: opts.LoadBalancerID},
		Spec:                   api.LoadBalancerTargetSpec{TargetIP: &opts.TargetIP},
	})
	if err != nil && lbtarget.Status.Code == 0 {
		return fmt.Errorf("error creating loadbalancer target: %w", err)
	}

	return rendererFactory.RenderObject("created", os.Stdout, lbtarget)
}
