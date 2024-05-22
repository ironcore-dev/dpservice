// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func GetInit(factory DPDKClientFactory, rendererFactory RendererFactory) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "init",
		Short:   "Indicates if the DPDK app has been initialized already",
		Example: "dpservice-cli get init",
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {

			return RunGetInit(
				cmd.Context(),
				factory,
				rendererFactory,
			)
		},
	}

	return cmd
}

func RunGetInit(
	ctx context.Context,
	dpdkClientFactory DPDKClientFactory,
	rendererFactory RendererFactory,
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

	init, err := client.CheckInitialized(ctx)
	if err != nil && init.Status.Code == 0 {
		return fmt.Errorf("error checking initialization status: %w", err)
	}

	return rendererFactory.RenderObject("", os.Stdout, init)
}
