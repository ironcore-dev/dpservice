// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"time"

	"github.com/ironcore-dev/dpservice-cli/renderer"
	"github.com/ironcore-dev/dpservice-cli/sources"
	"github.com/ironcore-dev/dpservice-go/api"
	"github.com/ironcore-dev/dpservice-go/client"
	apierrors "github.com/ironcore-dev/dpservice-go/errors"
	dpdkproto "github.com/ironcore-dev/dpservice-go/proto"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type DPDKClientFactory interface {
	NewClient(ctx context.Context) (client.Client, func() error, error)
}

type DPDKClientOptions struct {
	Address        string
	ConnectTimeout time.Duration
}

func (o *DPDKClientOptions) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&o.Address, "address", "localhost:1337", "dpservice address.")
	fs.DurationVar(&o.ConnectTimeout, "connect-timeout", 4*time.Second, "Timeout to connect to the dpservice.")
}

func (o *DPDKClientOptions) NewClient(ctx context.Context) (client.Client, func() error, error) {
	ctx, cancel := context.WithTimeout(ctx, o.ConnectTimeout)
	defer cancel()

	conn, err := grpc.DialContext(ctx, o.Address, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	if err != nil {
		return nil, nil, fmt.Errorf("error connecting to %s: %w", o.Address, err)
	}

	protoClient := dpdkproto.NewDPDKironcoreClient(conn)
	c := client.NewClient(protoClient)

	cleanup := conn.Close
	return c, cleanup, nil
}

func DpdkClose(cleanup func() error) {
	if err := cleanup(); err != nil {
		fmt.Printf("error cleaning up client: %s", err)
	}
}

func SubcommandRequired(cmd *cobra.Command, args []string) error {
	if err := cmd.Help(); err != nil {
		return err
	}
	return errors.New("subcommand is required")
}

func MultipleOfArgs(n int) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if len(args)%n != 0 {
			return fmt.Errorf("expected a multiple of %d args but got %d args", n, len(args))
		}
		return nil
	}
}

func CommandNames(cmds []*cobra.Command) []string {
	res := make([]string, len(cmds))
	for i, cmd := range cmds {
		res[i] = cmd.Name()
	}
	return res
}

type RendererOptions struct {
	Output string
	Pretty bool
	Wide   bool
}

func (o *RendererOptions) AddFlags(fs *pflag.FlagSet) {
	fs.StringVarP(&o.Output, "output", "o", o.Output, "Output format. [json|yaml|table|name]")
	fs.BoolVar(&o.Pretty, "pretty", o.Pretty, "Whether to render pretty output.")
	fs.BoolVarP(&o.Wide, "wide", "w", o.Wide, "Whether to render more info in table output.")
}

func (o *RendererOptions) GetWide() bool {
	return o.Wide
}

func (o *RendererOptions) NewRenderer(operation string, w io.Writer) (renderer.Renderer, error) {
	// TODO: Factor out instantiation of registry & make it more modular.
	registry := renderer.NewRegistry()

	if err := registry.Register("json", func(w io.Writer) renderer.Renderer {
		return renderer.NewJSON(w, o.Pretty)
	}); err != nil {
		return nil, err
	}

	if err := registry.Register("yaml", func(w io.Writer) renderer.Renderer {
		return renderer.NewYAML(w)
	}); err != nil {
		return nil, err
	}

	if err := registry.Register("name", func(w io.Writer) renderer.Renderer {
		return renderer.NewName(w, operation)
	}); err != nil {
		return nil, err
	}

	if err := registry.Register("table", func(w io.Writer) renderer.Renderer {
		renderer.DefaultTableConverter.SetWide(o.Wide)
		return renderer.NewTable(w, renderer.DefaultTableConverter)
	}); err != nil {
		return nil, err
	}

	output := o.Output
	if output == "" {
		output = "table"
	}

	return registry.New(output, w)
}

func (o *RendererOptions) RenderObject(operation string, w io.Writer, obj api.Object) error {
	if obj.GetStatus().Code != 0 {
		operation = fmt.Sprintf("server error: %d, %s", obj.GetStatus().Code, obj.GetStatus().Message)
		if o.Output == "table" {
			o.Output = "name"
		}
	}
	renderer, err := o.NewRenderer(operation, w)
	if err != nil {
		return fmt.Errorf("error creating renderer: %w", err)
	}
	if err := renderer.Render(obj); err != nil {
		return fmt.Errorf("error rendering %s: %w", obj.GetKind(), err)
	}
	if obj.GetStatus().Code != 0 {
		return fmt.Errorf(strconv.Itoa(apierrors.SERVER_ERROR))
	}
	return nil
}

func (o *RendererOptions) RenderList(operation string, w io.Writer, list api.List) error {
	if list.GetStatus().Code != 0 {
		operation = fmt.Sprintf("server error: %d, %s", list.GetStatus().Code, list.GetStatus().Message)
		if o.Output == "table" {
			o.Output = "name"
		}
	}
	renderer, err := o.NewRenderer(operation, w)
	if err != nil {
		return fmt.Errorf("error creating renderer: %w", err)
	}
	if err := renderer.Render(list); err != nil {
		return fmt.Errorf("error rendering %s: %w", list.GetItems()[0].GetKind(), err)
	}
	if list.GetStatus().Code != 0 {
		return fmt.Errorf(strconv.Itoa(apierrors.SERVER_ERROR))
	}
	return nil
}

type RendererFactory interface {
	NewRenderer(operation string, w io.Writer) (renderer.Renderer, error)
	RenderObject(operation string, w io.Writer, obj api.Object) error
	RenderList(operation string, w io.Writer, list api.List) error
	GetWide() bool
}

type SourcesOptions struct {
	Filename []string
}

func (o *SourcesOptions) AddFlags(fs *pflag.FlagSet) {
	fs.StringSliceVarP(&o.Filename, "filename", "f", o.Filename, "Filename, directory, or URL to file to use to create the resource")
}

func (o *SourcesOptions) NewIterator() (*sources.Iterator, error) {
	return sources.NewIterator(o.Filename), nil
}

type SourcesReaderFactory interface {
	NewIterator() (*sources.Iterator, error)
}

type RouteKey struct {
	Prefix     netip.Prefix
	NextHopVNI uint32
	NextHopIP  netip.Addr
}

func ParseRouteKey(prefixStr, nextHopVNIStr, nextHopIPStr string) (RouteKey, error) {
	prefix, err := netip.ParsePrefix(prefixStr)
	if err != nil {
		return RouteKey{}, fmt.Errorf("error parsing prefix: %w", err)
	}

	nextHopVNI, err := strconv.ParseUint(nextHopVNIStr, 10, 32)
	if err != nil {
		return RouteKey{}, fmt.Errorf("error parsing next hop vni: %w", err)
	}

	nextHopIP, err := netip.ParseAddr(nextHopIPStr)
	if err != nil {
		return RouteKey{}, fmt.Errorf("error parsing next hop ip: %w", err)
	}

	return RouteKey{
		Prefix:     prefix,
		NextHopVNI: uint32(nextHopVNI),
		NextHopIP:  nextHopIP,
	}, nil
}

func ParseRouteKeyArgs(args []string) ([]RouteKey, error) {
	if len(args)%3 != 0 {
		return nil, fmt.Errorf("expected args to be a multiple of 3 but got %d", len(args))
	}

	keys := make([]RouteKey, len(args)/3)
	for i := 0; i < len(args); i += 3 {
		key, err := ParseRouteKey(args[i], args[i+1], args[i+2])
		if err != nil {
			return nil, fmt.Errorf("[route key %d] %w", i, err)
		}

		keys[i/3] = key
	}
	return keys, nil
}

func ParsePrefixArgs(args []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, len(args))
	for i, arg := range args {
		prefix, err := netip.ParsePrefix(arg)
		if err != nil {
			return nil, fmt.Errorf("[prefix %d] %w", i, err)
		}

		prefixes[i] = prefix
	}
	return prefixes, nil
}

var (
	InterfaceAliases          = []string{"interface", "interfaces", "iface", "ifaces"}
	PrefixAliases             = []string{"prefix", "prefixes", "prfx", "prfxs"}
	RouteAliases              = []string{"route", "routes", "rt", "rts"}
	VirtualIPAliases          = []string{"virtualip", "virtualips", "vip", "vips"}
	LoadBalancerAliases       = []string{"loadbalancer", "loadbalancers", "loadbalancer", "lbs", "lb"}
	LoadBalancerPrefixAliases = []string{"loadbalancer-prefix", "loadbalancer-prefixes", "lbprefix", "lbprfx", "lbprfxs"}
	LoadBalancerTargetAliases = []string{"loadbalancer-target", "loadbalancer-targets", "lbtrgt", "lbtrgts", "lbtarget"}
	NatAliases                = []string{"nat", "translation"}
	NeighborNatAliases        = []string{"nnat", "ngbnat", "neighnat"}
	FirewallRuleAliases       = []string{"firewallrule", "fwrule", "fw-rule", "firewallrules", "fwrules", "fw-rules"}
)
