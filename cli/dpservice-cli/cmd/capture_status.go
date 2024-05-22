// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func CaptureStatus(dpdkClientFactory DPDKClientFactory, rendererFactory RendererFactory) *cobra.Command {

	cmd := &cobra.Command{
		Use:     "status",
		Short:   "Get the status of the packet capturing feature",
		Example: "dpservice-cli capture status",
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {

			return RunCaptureStatus(
				cmd.Context(),
				dpdkClientFactory,
				rendererFactory,
			)
		},
	}
	return cmd
}

func RunCaptureStatus(
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

	capture, err := client.CaptureStatus(ctx)
	if err != nil && capture.Status.Code == 0 {
		return fmt.Errorf("error checking initialization status: %w", err)
	}

	return rendererFactory.RenderObject("", os.Stdout, capture)
}
