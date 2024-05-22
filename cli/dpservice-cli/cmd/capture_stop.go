// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func CaptureStop(dpdkClientFactory DPDKClientFactory, rendererFactory RendererFactory) *cobra.Command {

	cmd := &cobra.Command{
		Use:     "stop",
		Short:   "Stop capturing packets for all interfaces",
		Example: "dpservice-cli capture stop",
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {

			return RunCaptureStop(
				cmd.Context(),
				dpdkClientFactory,
				rendererFactory,
			)
		},
	}
	return cmd
}

func RunCaptureStop(ctx context.Context, dpdkClientFactory DPDKClientFactory, rendererFactory RendererFactory) error {

	dpdkClient, cleanup, err := dpdkClientFactory.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("error creating dpdk client: %w", err)
	}

	defer DpdkClose(cleanup)

	captureStop, err := dpdkClient.CaptureStop(ctx)

	if err != nil && captureStop.Status.Code == 0 {
		return fmt.Errorf("error stopping capturing: %w", err)
	}

	return rendererFactory.RenderObject("Packet capturing stopped \n", os.Stdout, captureStop)
}
