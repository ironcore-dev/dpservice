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

func Delete(factory DPDKClientFactory) *cobra.Command {
	sourcesOptions := &SourcesOptions{}
	rendererOptions := &RendererOptions{Output: "name"}

	cmd := &cobra.Command{
		Use:     "delete [command]",
		Aliases: []string{"del"},
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			return RunDelete(ctx, factory, rendererOptions, sourcesOptions)
		},
	}

	rendererOptions.AddFlags(cmd.PersistentFlags())

	sourcesOptions.AddFlags(cmd.Flags())

	subcommands := []*cobra.Command{
		DeleteInterface(factory, rendererOptions),
		DeletePrefix(factory, rendererOptions),
		DeleteRoute(factory, rendererOptions),
		DeleteVirtualIP(factory, rendererOptions),
		DeleteLoadBalancer(factory, rendererOptions),
		DeleteLoadBalancerPrefix(factory, rendererOptions),
		DeleteLoadBalancerTarget(factory, rendererOptions),
		DeleteNat(factory, rendererOptions),
		DeleteNeighborNat(factory, rendererOptions),
		DeleteFirewallRule(factory, rendererOptions),
	}

	cmd.Short = fmt.Sprintf("Deletes one of %v", CommandNames(subcommands))
	cmd.Long = fmt.Sprintf("Deletes one of %v", CommandNames(subcommands))

	cmd.AddCommand(subcommands...)

	return cmd
}

func RunDelete(
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

	renderer, err := rendererFactory.NewRenderer("deleted", os.Stdout)
	if err != nil {
		return fmt.Errorf("error creating renderer: %w", err)
	}

	dc := dynamic.NewFromStructured(client)

	iterator, err := sourcesReaderFactory.NewIterator()
	if err != nil {
		return fmt.Errorf("error creating sources iterator: %w", err)
	}

	objs, err := sources.CollectObjects(iterator, runtime.DefaultScheme)
	if err != nil {
		return fmt.Errorf("error collecting objects: %w", err)
	}

	for _, obj := range objs {
		key := dynamic.ObjectKeyFromObject(obj)

		res, err := dc.Delete(ctx, obj)
		if strings.Contains(err.Error(), errors.StatusErrorString) {
			r := reflect.ValueOf(res)
			err := reflect.Indirect(r).FieldByName("Status").FieldByName("Error")
			msg := reflect.Indirect(r).FieldByName("Status").FieldByName("Message")
			fmt.Printf("Error deleting %T %s: Server error: %v %v\n", res, key, err, msg)
			continue
		}
		if err != nil {
			fmt.Printf("Error deleting %T %s: %v\n", res, key, err)
			continue
		}

		if err := renderer.Render(obj); err != nil {
			return fmt.Errorf("error rendering %T: %w", obj, err)
		}
	}

	return nil
}
