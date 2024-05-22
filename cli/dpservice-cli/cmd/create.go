// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"strings"

	"github.com/ironcore-dev/dpservice-cli/dpdk/client/dynamic"
	"github.com/ironcore-dev/dpservice-cli/dpdk/runtime"
	"github.com/ironcore-dev/dpservice-cli/sources"
	"github.com/ironcore-dev/dpservice-go/errors"
	"github.com/spf13/cobra"
)

func Create(factory DPDKClientFactory) *cobra.Command {
	rendererOptions := &RendererOptions{Output: "name"}
	sourcesOptions := &SourcesOptions{}

	cmd := &cobra.Command{
		Use:     "create [command]",
		Aliases: []string{"add"},
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			return RunCreate(ctx, factory, rendererOptions, sourcesOptions)
		},
	}

	rendererOptions.AddFlags(cmd.PersistentFlags())

	sourcesOptions.AddFlags(cmd.Flags())

	subcommands := []*cobra.Command{
		CreateInterface(factory, rendererOptions),
		CreatePrefix(factory, rendererOptions),
		CreateRoute(factory, rendererOptions),
		CreateVirtualIP(factory, rendererOptions),
		CreateLoadBalancer(factory, rendererOptions),
		CreateLoadBalancerPrefix(factory, rendererOptions),
		CreateLoadBalancerTarget(factory, rendererOptions),
		CreateNat(factory, rendererOptions),
		CreateNeighborNat(factory, rendererOptions),
		CreateFirewallRule(factory, rendererOptions),
	}

	cmd.Short = fmt.Sprintf("Creates one of %v", CommandNames(subcommands))
	cmd.Long = fmt.Sprintf("Creates one of %v", CommandNames(subcommands))

	cmd.AddCommand(
		subcommands...,
	)

	return cmd
}

func RunCreate(
	ctx context.Context,
	dpdkClientFactory DPDKClientFactory,
	rendererFactory RendererFactory,
	sourcesReaderFactory SourcesReaderFactory,
) error {
	client, cleanup, err := dpdkClientFactory.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("error creating dpdk client: %w", err)
	}
	defer func() {
		if err := cleanup(); err != nil {
			fmt.Printf("Error cleaning up client: %v\n", err)
		}
	}()

	dc := dynamic.NewFromStructured(client)

	renderer, err := rendererFactory.NewRenderer("created", os.Stdout)
	if err != nil {
		return fmt.Errorf("error creating renderer: %w", err)
	}

	iterator, err := sourcesReaderFactory.NewIterator()
	if err != nil {
		return fmt.Errorf("error creating sources iterator: %w", err)
	}

	objs, err := sources.CollectObjects(iterator, runtime.DefaultScheme)
	if err != nil {
		return fmt.Errorf("error collecting objects: %w", err)
	}

	for _, obj := range objs {
		res, err := dc.Create(ctx, obj)
		if strings.Contains(err.Error(), errors.StatusErrorString) {
			r := reflect.ValueOf(res)
			err := reflect.Indirect(r).FieldByName("Status").FieldByName("Error")
			msg := reflect.Indirect(r).FieldByName("Status").FieldByName("Message")
			fmt.Printf("Error creating %T: Server error: %v %v\n", res, err, msg)
			continue
		}
		if err != nil {
			fmt.Printf("Error creating %T: %v\n", obj, err)
			continue
		}

		if err := renderer.Render(res); err != nil {
			return fmt.Errorf("error rendering %T: %w", obj, err)
		}
	}

	return nil
}
