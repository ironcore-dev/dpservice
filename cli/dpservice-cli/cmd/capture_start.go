// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/ironcore-dev/dpservice-cli/flag"
	"github.com/ironcore-dev/dpservice-cli/util"
	"github.com/ironcore-dev/dpservice-go/api"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func CaptureStart(dpdkClientFactory DPDKClientFactory, rendererFactory RendererFactory) *cobra.Command {
	var (
		opts CaptureStartOptions
	)

	cmd := &cobra.Command{
		Use:     "start <--sink-node-ip> <--udp-src-port> <--udp-dst-port> [--pf] [--vf]",
		Short:   "Start capturing packets",
		Example: "dpservice-cli capture start --sink-node-ip=fc00:2::64:0:1 --udp-src-port=30000 --udp-dst-port=30100 --pf=0(must be 0 due to hardware limitation) --vf=vm1,vm2,vm3",
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {

			return RunCaptureStart(
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

type CaptureStartOptions struct {
	SinkNodeIP    netip.Addr
	UdpSrcPort    uint32
	UdpDstPort    uint32
	PfIndexString string
	VfIndexString string
}

func (o *CaptureStartOptions) AddFlags(fs *pflag.FlagSet) {
	flag.AddrVar(fs, &o.SinkNodeIP, "sink-node-ip", o.SinkNodeIP, "IP address of the sink node")
	fs.Uint32Var(&o.UdpSrcPort, "udp-src-port", o.UdpSrcPort, "UDP source port")
	fs.Uint32Var(&o.UdpDstPort, "udp-dst-port", o.UdpDstPort, "UDP destination port")
	fs.StringVar(&o.PfIndexString, "pf", "", "PF index")
	fs.StringVar(&o.VfIndexString, "vf", "", "VF index")
}

func (o *CaptureStartOptions) MarkRequiredFlags(cmd *cobra.Command) error {
	for _, name := range []string{
		"sink-node-ip",
		"udp-src-port",
		"udp-dst-port",
	} {
		if err := cmd.MarkFlagRequired(name); err != nil {
			return err
		}
	}
	return nil
}

func StringPFIndexToPFIndex(indexString string) ([]string, error) {
	indexes := strings.Split(indexString, ",")

	if len(indexes) > 2 {
		return nil, fmt.Errorf("too many pf indexes specified")
	}

	for _, index := range indexes {
		indexInt, err := strconv.Atoi(index)
		if err != nil {
			return nil, fmt.Errorf("error parsing pf index: %w", err)
		}
		if indexInt > 1 {
			return nil, fmt.Errorf("pf index must be 0 or 1")
		}
	}

	return indexes, nil
}

func StringVFIdToVFId(idString string) []string {
	return strings.Split(idString, ",")
}

func RunCaptureStart(ctx context.Context, dpdkClientFactory DPDKClientFactory, rendererFactory RendererFactory, opts CaptureStartOptions) error {

	dpdkClient, cleanup, err := dpdkClientFactory.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("error creating dpdk client: %w", err)
	}

	defer DpdkClose(cleanup)

	interfaces := make([]api.CaptureInterface, 0)

	if opts.PfIndexString != "" {
		pfIndexes, err := StringPFIndexToPFIndex(opts.PfIndexString)
		if err != nil {
			return fmt.Errorf("error converting PF indexes: %w", err)
		}
		for _, pfIndex := range pfIndexes {
			interfaces = append(interfaces, api.CaptureInterface{
				InterfaceType: "pf",
				InterfaceInfo: pfIndex,
			})
		}
	}

	if opts.VfIndexString != "" {
		vfIndexes := StringVFIdToVFId(opts.VfIndexString)

		for _, vfIndex := range vfIndexes {
			interfaces = append(interfaces, api.CaptureInterface{
				InterfaceType: "vf",
				InterfaceInfo: vfIndex,
			})
		}
	}

	capture, err := dpdkClient.CaptureStart(ctx, &api.CaptureStart{
		TypeMeta: api.TypeMeta{Kind: api.CaptureStartKind},
		CaptureStartMeta: api.CaptureStartMeta{
			Config: &api.CaptureConfig{
				SinkNodeIP: &opts.SinkNodeIP,
				UdpSrcPort: opts.UdpSrcPort,
				UdpDstPort: opts.UdpDstPort,
			},
		},
		Spec: api.CaptureStartSpec{
			Interfaces: interfaces,
		},
	})

	if err != nil && capture.Status.Code == 0 {
		return fmt.Errorf("error initializing packet capturing: %w", err)
	}

	return rendererFactory.RenderObject(fmt.Sprintf("Packet capturing initialized: %s\n", capture.CaptureStartMeta.Config.SinkNodeIP.String()), os.Stdout, capture)
}
