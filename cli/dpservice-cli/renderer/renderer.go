// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package renderer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"

	"github.com/ghodss/yaml"
	"github.com/ironcore-dev/dpservice-go/api"
	dpdkproto "github.com/ironcore-dev/dpservice-go/proto"
	"github.com/jedib0t/go-pretty/v6/table"
)

type Renderer interface {
	Render(v any) error
}

type JSON struct {
	w      io.Writer
	pretty bool
}

func NewJSON(w io.Writer, pretty bool) *JSON {
	return &JSON{w, pretty}
}

func (j *JSON) Render(v any) error {
	enc := json.NewEncoder(j.w)
	if j.pretty {
		enc.SetIndent("", "  ")
	}
	return enc.Encode(v)
}

type YAML struct {
	w io.Writer
}

func NewYAML(w io.Writer) *YAML {
	return &YAML{w}
}

func (y *YAML) Render(v any) error {
	jsonData, err := json.Marshal(v)
	if err != nil {
		return err
	}

	data, err := yaml.JSONToYAML(jsonData)
	if err != nil {
		return err
	}

	_, err = io.Copy(y.w, bytes.NewReader(data))
	return err
}

type Name struct {
	w         io.Writer
	operation string
}

func NewName(w io.Writer, operation string) *Name {
	return &Name{
		w:         w,
		operation: operation,
	}
}

func (n *Name) Render(v any) error {
	objs, err := getObjs(v)
	if err != nil {
		if err.Error() == "empty list" {
			return n.renderList(v)
		}
		return err
	}

	for _, obj := range objs {
		if err := n.renderObject(obj); err != nil {
			return err
		}
	}
	return nil
}

func (n *Name) renderObject(obj api.Object) error {
	var parts []string
	if kind := obj.GetKind(); kind != "" {
		parts = append(parts, fmt.Sprintf("%s/%s", strings.ToLower(kind), obj.GetName()))
	} else {
		parts = append(parts, obj.GetName())
	}

	if n.operation != "" {
		parts = append(parts, n.operation)
	}

	_, err := fmt.Fprintf(n.w, "%s\n", strings.Join(parts, " "))
	return err
}

func (n *Name) renderList(list any) error {
	var parts []string

	parts = append(parts, strings.ToLower(strings.Split(reflect.TypeOf(list).String(), ".")[1]))
	if n.operation != "" {
		parts = append(parts, n.operation)
	}

	_, err := fmt.Fprintf(n.w, "%s\n", strings.Join(parts, " "))
	return err
}

func getObjs(v any) ([]api.Object, error) {
	switch v := v.(type) {
	case api.Object:
		return []api.Object{v}, nil
	case api.List:
		if v.GetStatus().Code != 0 {
			return nil, fmt.Errorf("empty list")
		}
		return v.GetItems(), nil
	default:
		return nil, fmt.Errorf("unsupported type %T", v)
	}
}

type Table struct {
	w              io.Writer
	tableConverter TableConverter
}

func NewTable(w io.Writer, converter TableConverter) *Table {
	return &Table{w, converter}
}

type TableData struct {
	Headers []any
	Columns [][]any
}

type TableConverter interface {
	ConvertToTable(v any) (*TableData, error)
}

type defaultTableConverter struct {
	Wide bool
}

func (t *defaultTableConverter) SetWide(wide bool) {
	t.Wide = wide
}

var DefaultTableConverter = defaultTableConverter{}

func (t defaultTableConverter) ConvertToTable(v any) (*TableData, error) {
	switch obj := v.(type) {
	case *api.LoadBalancer:
		return t.loadBalancerTable(*obj)
	case *api.LoadBalancerTarget:
		return t.loadBalancerTargetTable([]api.LoadBalancerTarget{*obj})
	case *api.LoadBalancerTargetList:
		return t.loadBalancerTargetTable(obj.Items)
	case *api.Interface:
		return t.interfaceTable([]api.Interface{*obj})
	case *api.InterfaceList:
		return t.interfaceTable(obj.Items)
	case *api.Prefix:
		return t.prefixTable([]api.Prefix{*obj})
	case *api.PrefixList:
		return t.prefixTable(obj.Items)
	case *api.Route:
		return t.routeTable([]api.Route{*obj})
	case *api.RouteList:
		return t.routeTable(obj.Items)
	case *api.VirtualIP:
		return t.virtualIPTable([]api.VirtualIP{*obj})
	case *api.Nat:
		return t.natTable([]api.Nat{*obj})
	case *api.NeighborNat:
		return t.neighborNatTable([]api.NeighborNat{*obj})
	case *api.NatList:
		return t.natTable(obj.Items)
	case *api.FirewallRule:
		return t.fwruleTable([]api.FirewallRule{*obj})
	case *api.FirewallRuleList:
		return t.fwruleTable(obj.Items)
	case *api.Initialized:
		return t.initializedTable(*obj)
	case *api.Vni:
		return t.vniTable(*obj)
	case *api.Version:
		return t.versionTable(*obj)
	case *api.CaptureStart:
		return t.captureStartTable(*obj)
	case *api.CaptureStop:
		return t.captureStopTable(*obj)
	case *api.CaptureStatus:
		return t.captureStatusTable(*obj)
	default:
		return nil, fmt.Errorf("unsupported type %T", v)
	}
}

func (t defaultTableConverter) loadBalancerTable(lb api.LoadBalancer) (*TableData, error) {
	headers := []any{"ID", "VNI", "LbVipIP", "Lbports", "UnderlayRoute"}

	columns := make([][]any, 1)

	var ports = make([]string, 0, len(lb.Spec.Lbports))
	for _, port := range lb.Spec.Lbports {
		p := dpdkproto.Protocol_name[int32(port.Protocol)] + "/" + strconv.Itoa(int(port.Port))
		ports = append(ports, p)
	}
	columns[0] = []any{lb.ID, lb.Spec.VNI, lb.Spec.LbVipIP, ports, lb.Spec.UnderlayRoute}

	return &TableData{
		Headers: headers,
		Columns: columns,
	}, nil
}

func (t defaultTableConverter) loadBalancerTargetTable(lbtargets []api.LoadBalancerTarget) (*TableData, error) {
	headers := []any{"IpVersion", "Address"}

	columns := make([][]any, len(lbtargets))
	for i, lbtarget := range lbtargets {
		columns[i] = []any{
			api.NetIPAddrToProtoIPVersion(lbtarget.Spec.TargetIP),
			lbtarget.Spec.TargetIP,
		}
	}

	return &TableData{
		Headers: headers,
		Columns: columns,
	}, nil
}

func (t defaultTableConverter) interfaceTable(ifaces []api.Interface) (*TableData, error) {
	headers := []any{"ID", "VNI", "Device", "IPv4", "IPv6", "UnderlayRoute", "TotalMeterRate", "PublicMeterRate"}
	vfNeeded := isColumnNeeded(ifaces, "Spec.VirtualFunction")
	if vfNeeded {
		headers = append(headers, "VirtualFunction")
	}
	natNeeded := true
	if t.Wide && natNeeded {
		headers = append(headers, "Nat")
	}
	vipNeeded := true
	if t.Wide && vipNeeded {
		headers = append(headers, "VirtualIP")
	}

	columns := make([][]any, len(ifaces))
	for i, iface := range ifaces {
		columns[i] = []any{iface.ID, iface.Spec.VNI, iface.Spec.Device, iface.Spec.IPv4, iface.Spec.IPv6, iface.Spec.UnderlayRoute, iface.Spec.Metering.TotalRate, iface.Spec.Metering.PublicRate}
		if iface.Spec.VirtualFunction != nil {
			columns[i] = append(columns[i], iface.Spec.VirtualFunction.Name)
		} else if vfNeeded {
			columns[i] = append(columns[i], "")
		}
		if t.Wide && iface.Spec.Nat != nil {
			columns[i] = append(columns[i], iface.Spec.Nat.String())
		} else if natNeeded {
			columns[i] = append(columns[i], "")
		}
		if t.Wide && iface.Spec.VIP != nil {
			columns[i] = append(columns[i], iface.Spec.VIP.Spec.IP)
		} else if vipNeeded {
			columns[i] = append(columns[i], "")
		}
	}

	return &TableData{
		Headers: headers,
		Columns: columns,
	}, nil
}

func (t defaultTableConverter) prefixTable(prefixes []api.Prefix) (*TableData, error) {
	headers := []any{"Prefix", "UnderlayRoute"}

	columns := make([][]any, len(prefixes))
	for i, prefix := range prefixes {
		columns[i] = []any{prefix.Spec.Prefix, prefix.Spec.UnderlayRoute}
	}

	return &TableData{
		Headers: headers,
		Columns: columns,
	}, nil
}

func (t defaultTableConverter) routeTable(routes []api.Route) (*TableData, error) {
	headers := []any{"Prefix", "VNI", "NextHopVNI", "NextHopIP"}

	columns := make([][]any, len(routes))
	for i, route := range routes {
		columns[i] = []any{route.Spec.Prefix, route.VNI, route.Spec.NextHop.VNI, route.Spec.NextHop.IP}
	}

	return &TableData{
		Headers: headers,
		Columns: columns,
	}, nil
}

func (t defaultTableConverter) virtualIPTable(virtualIPs []api.VirtualIP) (*TableData, error) {
	headers := []any{"InterfaceID", "VirtualIP", "UnderlayRoute"}

	columns := make([][]any, len(virtualIPs))
	for i, virtualIP := range virtualIPs {
		columns[i] = []any{virtualIP.InterfaceID, virtualIP.Spec.IP, virtualIP.Spec.UnderlayRoute}
	}

	return &TableData{
		Headers: headers,
		Columns: columns,
	}, nil
}

func (t defaultTableConverter) natTable(nats []api.Nat) (*TableData, error) {
	var headers []any
	// if command was get nat or there are no nats
	if len(nats) > 0 && nats[0].InterfaceID != "" {
		headers = []any{"InterfaceID", "IP", "MinPort", "MaxPort", "UnderlayRoute"}
		// if command was list nats
	} else {
		headers = []any{"VNI", "IP", "MinPort", "MaxPort", "UnderlayRoute", "NatType"}
	}

	columns := make([][]any, len(nats))
	for i, nat := range nats {
		// if command was get nat or there are no nats
		if len(nats) > 0 && nats[0].InterfaceID != "" {
			columns[i] = []any{nat.NatMeta.InterfaceID, nat.Spec.NatIP, nat.Spec.MinPort, nat.Spec.MaxPort, nat.Spec.UnderlayRoute}
			// if command was list nats
		} else {
			columns[i] = []any{nat.Spec.Vni, nat.Spec.NatIP, nat.Spec.MinPort, nat.Spec.MaxPort, nat.Spec.UnderlayRoute}
			if len(nats) > 0 && nats[i].Spec.UnderlayRoute == nil {
				columns[i] = append(columns[i], "Local")
			} else {
				columns[i] = append(columns[i], "Neighbor")
			}
		}
	}

	return &TableData{
		Headers: headers,
		Columns: columns,
	}, nil
}

func (t defaultTableConverter) neighborNatTable(nats []api.NeighborNat) (*TableData, error) {

	headers := []any{"VNI", "NatIP", "MinPort", "MaxPort", "UnderlayRoute"}

	columns := make([][]any, len(nats))
	for i, nat := range nats {

		columns[i] = []any{nat.Spec.Vni, nat.NeighborNatMeta.NatIP, nat.Spec.MinPort, nat.Spec.MaxPort, nat.Spec.UnderlayRoute}

	}

	return &TableData{
		Headers: headers,
		Columns: columns,
	}, nil
}

func (t defaultTableConverter) fwruleTable(fwrules []api.FirewallRule) (*TableData, error) {
	headers := []any{"InterfaceID", "RuleID", "Direction", "Src", "Dst", "Action", "Protocol", "Priority"}

	columns := make([][]any, len(fwrules))
	for i, fwrule := range fwrules {
		columns[i] = []any{
			fwrule.FirewallRuleMeta.InterfaceID,
			fwrule.Spec.RuleID,
			fwrule.Spec.TrafficDirection,
			fwrule.Spec.SourcePrefix,
			fwrule.Spec.DestinationPrefix,
			fwrule.Spec.FirewallAction,
			fwrule.Spec.ProtocolFilter.String(),
			fwrule.Spec.Priority,
		}
	}

	return &TableData{
		Headers: headers,
		Columns: columns,
	}, nil
}

func (t defaultTableConverter) vniTable(vni api.Vni) (*TableData, error) {
	headers := []any{"VNI", "VniType", "inUse"}
	columns := make([][]any, 1)
	columns[0] = []any{vni.VniMeta.VNI, vni.VniMeta.VniType, vni.Spec.InUse}

	return &TableData{
		Headers: headers,
		Columns: columns,
	}, nil
}

func (t defaultTableConverter) versionTable(version api.Version) (*TableData, error) {
	headers := []any{"ServiceProto", "ServiceVersion", "ClientName", "ClientProto", "ClientVersion"}
	columns := make([][]any, 1)
	columns[0] = []any{
		version.Spec.ServiceProtocol,
		version.Spec.ServiceVersion,
		version.ClientName,
		version.ClientProtocol,
		version.ClientVersion,
	}

	return &TableData{
		Headers: headers,
		Columns: columns,
	}, nil
}

func (t defaultTableConverter) initializedTable(initialized api.Initialized) (*TableData, error) {
	headers := []any{"UUID"}
	columns := make([][]any, 1)
	columns[0] = []any{initialized.Spec.UUID}

	return &TableData{
		Headers: headers,
		Columns: columns,
	}, nil
}

func (t defaultTableConverter) captureStartTable(captureStart api.CaptureStart) (*TableData, error) {
	headers := []any{"SinkNodeIP", "UdpSrcPort", "UdpDstPort", "PF Interfaces", "VF Interfaces"}
	columns := make([][]any, 1)

	pfInterfaces := ""
	vfInterfaces := ""

	for _, iface := range captureStart.Spec.Interfaces {

		if iface.InterfaceType == "pf" {
			pfInterfaces += iface.InterfaceInfo + " "
		} else {
			vfInterfaces += iface.InterfaceInfo + " "
		}
	}

	columns[0] = []any{captureStart.CaptureStartMeta.Config.SinkNodeIP,
		captureStart.CaptureStartMeta.Config.UdpSrcPort, captureStart.CaptureStartMeta.Config.UdpDstPort,
		pfInterfaces, vfInterfaces}

	return &TableData{
		Headers: headers,
		Columns: columns,
	}, nil
}

func (t defaultTableConverter) captureStopTable(captureStop api.CaptureStop) (*TableData, error) {
	headers := []any{"Stopped Interface"}
	columns := make([][]any, 1)

	columns[0] = []any{captureStop.Spec.InterfaceCount}

	return &TableData{
		Headers: headers,
		Columns: columns,
	}, nil
}

func (t defaultTableConverter) captureStatusTable(captureStatus api.CaptureStatus) (*TableData, error) {
	headers := []any{"Operation Status", "SinkNodeIP", "UdpSrcPort", "UdpDstPort", "PF Interfaces", "VF Interfaces"}
	columns := make([][]any, 1)

	pfInterfaces := ""
	vfInterfaces := ""

	for _, iface := range captureStatus.Spec.Interfaces {

		if iface.InterfaceType == "pf" {
			pfInterfaces += iface.InterfaceInfo + " "
		} else {
			vfInterfaces += iface.InterfaceInfo + " "
		}
	}

	if !captureStatus.Spec.OperationStatus {
		columns[0] = []any{"NOT_ACTIVE", "", "", "", "", ""}
	} else {
		columns[0] = []any{"ACTIVE", captureStatus.Spec.Config.SinkNodeIP,
			captureStatus.Spec.Config.UdpSrcPort, captureStatus.Spec.Config.UdpDstPort,
			pfInterfaces, vfInterfaces}
	}

	return &TableData{
		Headers: headers,
		Columns: columns,
	}, nil
}

var (
	lightBoxStyle = table.BoxStyle{
		BottomLeft:       "",
		BottomRight:      "",
		BottomSeparator:  "",
		EmptySeparator:   " ",
		Left:             "",
		LeftSeparator:    "",
		MiddleHorizontal: "",
		MiddleSeparator:  "",
		MiddleVertical:   " ",
		PaddingLeft:      " ",
		PaddingRight:     " ",
		PageSeparator:    "\n",
		Right:            "",
		RightSeparator:   "",
		TopLeft:          "",
		TopRight:         "",
		TopSeparator:     "",
		UnfinishedRow:    "",
	}
	tableStyle = table.Style{Box: lightBoxStyle}
)

func (t *Table) Render(v any) error {
	data, err := t.tableConverter.ConvertToTable(v)
	if err != nil {
		return err
	}

	tw := table.NewWriter()
	tw.SetStyle(tableStyle)
	tw.SetOutputMirror(t.w)

	tw.AppendHeader(data.Headers)
	for _, col := range data.Columns {
		tw.AppendRow(col)
	}

	tw.Render()
	return nil
}

type NewFunc func(w io.Writer) Renderer

type Registry struct {
	newFuncByName map[string]NewFunc
}

func NewRegistry() *Registry {
	return &Registry{
		newFuncByName: make(map[string]NewFunc),
	}
}

func (r *Registry) Register(name string, newFunc NewFunc) error {
	if _, ok := r.newFuncByName[name]; ok {
		return fmt.Errorf("renderer %q is already registered", name)
	}

	r.newFuncByName[name] = newFunc
	return nil
}

func (r *Registry) New(name string, w io.Writer) (Renderer, error) {
	newFunc, ok := r.newFuncByName[name]
	if !ok {
		return nil, fmt.Errorf("unknown renderer %q", name)
	}

	return newFunc(w), nil
}

// iterate over objects to check if it has any non nil value in given field
func isColumnNeeded(objs interface{}, field string) bool {
	fields := strings.Split(field, ".")
	v := reflect.ValueOf(objs)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	for i := 0; i < v.Len(); i++ {
		r := reflect.ValueOf(v.Index(i).Interface())
		f := reflect.Indirect(r).FieldByName(fields[0]).FieldByName(fields[1])
		if !f.IsZero() {
			return true
		}
	}
	return false
}
