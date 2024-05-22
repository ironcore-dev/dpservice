// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"fmt"
	"net/netip"
	"reflect"

	proto "github.com/ironcore-dev/dpservice-go/proto"
)

type Object interface {
	GetKind() string
	GetName() string
	GetStatus() Status
}

type List interface {
	GetItems() []Object
	GetStatus() Status
}

type TypeMeta struct {
	Kind string `json:"kind"`
}

func (m *TypeMeta) GetKind() string {
	return m.Kind
}

type Status struct {
	Code    uint32 `json:"code"`
	Message string `json:"message"`
}

func (status *Status) String() string {
	if status.Code == 0 {
		return status.Message
	}
	return fmt.Sprintf("Code: %d, Message: %s", status.Code, status.Message)
}

// Route section
type RouteList struct {
	TypeMeta      `json:",inline"`
	RouteListMeta `json:"metadata"`
	Status        Status  `json:"status"`
	Items         []Route `json:"items"`
}

type RouteListMeta struct {
	VNI uint32 `json:"vni"`
}

func (l *RouteList) GetItems() []Object {
	res := make([]Object, len(l.Items))
	for i := range l.Items {
		res[i] = &l.Items[i]
	}
	return res
}

func (m *RouteList) GetStatus() Status {
	return m.Status
}

type Route struct {
	TypeMeta  `json:",inline"`
	RouteMeta `json:"metadata"`
	Spec      RouteSpec `json:"spec"`
	Status    Status    `json:"status"`
}

type RouteMeta struct {
	VNI uint32 `json:"vni"`
}

func (m *Route) GetName() string {
	return fmt.Sprintf("%s-%d", m.Spec.Prefix, m.Spec.NextHop.VNI)
}

func (m *Route) GetStatus() Status {
	return m.Status
}

type RouteSpec struct {
	Prefix  *netip.Prefix `json:"prefix,omitempty"`
	NextHop *RouteNextHop `json:"next_hop,omitempty"`
}

type RouteNextHop struct {
	VNI uint32      `json:"vni"`
	IP  *netip.Addr `json:"address,omitempty"`
}

// Prefix section
type PrefixList struct {
	TypeMeta       `json:",inline"`
	PrefixListMeta `json:"metadata"`
	Status         Status   `json:"status"`
	Items          []Prefix `json:"items"`
}

type PrefixListMeta struct {
	InterfaceID string `json:"interface_id"`
}

func (l *PrefixList) GetItems() []Object {
	res := make([]Object, len(l.Items))
	for i := range l.Items {
		res[i] = &l.Items[i]
	}
	return res
}

func (m *PrefixList) GetStatus() Status {
	return m.Status
}

type Prefix struct {
	TypeMeta   `json:",inline"`
	PrefixMeta `json:"metadata"`
	Spec       PrefixSpec `json:"spec"`
	Status     Status     `json:"status"`
}

type PrefixMeta struct {
	InterfaceID string `json:"interface_id"`
}

func (m *Prefix) GetName() string {
	return m.Spec.Prefix.String()
}

func (m *Prefix) GetStatus() Status {
	return m.Status
}

type PrefixSpec struct {
	Prefix        netip.Prefix `json:"prefix"`
	UnderlayRoute *netip.Addr  `json:"underlay_route,omitempty"`
}

// VirtualIP section
type VirtualIP struct {
	TypeMeta      `json:",inline"`
	VirtualIPMeta `json:"metadata"`
	Spec          VirtualIPSpec `json:"spec"`
	Status        Status        `json:"status"`
}

type VirtualIPMeta struct {
	InterfaceID string `json:"interface_id"`
}

func (m *VirtualIP) GetName() string {
	return "on interface: " + m.VirtualIPMeta.InterfaceID
}

func (m *VirtualIP) GetStatus() Status {
	return m.Status
}

type VirtualIPSpec struct {
	IP            *netip.Addr `json:"vip_ip"`
	UnderlayRoute *netip.Addr `json:"underlay_route,omitempty"`
}

// LoadBalancer section
type LoadBalancer struct {
	TypeMeta         `json:",inline"`
	LoadBalancerMeta `json:"metadata"`
	Spec             LoadBalancerSpec `json:"spec"`
	Status           Status           `json:"status"`
}

type LoadBalancerMeta struct {
	ID string `json:"id"`
}

func (m *LoadBalancerMeta) GetName() string {
	return m.ID
}

func (m *LoadBalancer) GetStatus() Status {
	return m.Status
}

type LoadBalancerSpec struct {
	VNI           uint32      `json:"vni"`
	LbVipIP       *netip.Addr `json:"loadbalanced_ip,omitempty"`
	Lbports       []LBPort    `json:"loadbalanced_ports,omitempty"`
	UnderlayRoute *netip.Addr `json:"underlay_route,omitempty"`
}

type LBPort struct {
	Protocol uint32 `json:"protocol"`
	Port     uint32 `json:"port"`
}

type LoadBalancerTarget struct {
	TypeMeta               `json:",inline"`
	LoadBalancerTargetMeta `json:"metadata"`
	Spec                   LoadBalancerTargetSpec `json:"spec"`
	Status                 Status                 `json:"status"`
}

type LoadBalancerTargetMeta struct {
	LoadbalancerID string `json:"loadbalancer_id"`
}

func (m *LoadBalancerTarget) GetName() string {
	return "on loadbalancer: " + m.LoadBalancerTargetMeta.LoadbalancerID
}

func (m *LoadBalancerTarget) GetStatus() Status {
	return m.Status
}

type LoadBalancerTargetSpec struct {
	TargetIP *netip.Addr `json:"target_ip,omitempty"`
}

type LoadBalancerTargetList struct {
	TypeMeta                   `json:",inline"`
	LoadBalancerTargetListMeta `json:"metadata"`
	Status                     Status               `json:"status"`
	Items                      []LoadBalancerTarget `json:"items"`
}

type LoadBalancerTargetListMeta struct {
	LoadBalancerID string `json:"loadbalancer_id"`
}

func (l *LoadBalancerTargetList) GetItems() []Object {
	res := make([]Object, len(l.Items))
	for i := range l.Items {
		res[i] = &l.Items[i]
	}
	return res
}

func (m *LoadBalancerTargetList) GetStatus() Status {
	return m.Status
}

type LoadBalancerPrefix struct {
	TypeMeta               `json:",inline"`
	LoadBalancerPrefixMeta `json:"metadata"`
	Spec                   LoadBalancerPrefixSpec `json:"spec"`
	Status                 Status                 `json:"status"`
}

type LoadBalancerPrefixMeta struct {
	InterfaceID string `json:"interface_id"`
}

func (m *LoadBalancerPrefix) GetName() string {
	return m.Spec.Prefix.String()
}

func (m *LoadBalancerPrefix) GetStatus() Status {
	return m.Status
}

type LoadBalancerPrefixSpec struct {
	Prefix        netip.Prefix `json:"prefix"`
	UnderlayRoute *netip.Addr  `json:"underlay_route,omitempty"`
}

// Interface section
type Interface struct {
	TypeMeta      `json:",inline"`
	InterfaceMeta `json:"metadata"`
	Spec          InterfaceSpec `json:"spec"`
	Status        Status        `json:"status"`
}

type InterfaceMeta struct {
	ID string `json:"id"`
}

type PXE struct {
	Server   string `json:"next_server,omitempty"`
	FileName string `json:"boot_filename,omitempty"`
}

type MeteringParams struct {
	TotalRate  uint64 `json:"total_rate,omitempty"`
	PublicRate uint64 `json:"public_rate,omitempty"`
}

func (m *InterfaceMeta) GetName() string {
	return m.ID
}

func (m *Interface) GetStatus() Status {
	return m.Status
}

type InterfaceSpec struct {
	VNI             uint32           `json:"vni"`
	Device          string           `json:"device,omitempty"`
	IPv4            *netip.Addr      `json:"primary_ipv4,omitempty"`
	IPv6            *netip.Addr      `json:"primary_ipv6,omitempty"`
	UnderlayRoute   *netip.Addr      `json:"underlay_route,omitempty"`
	VirtualFunction *VirtualFunction `json:"virtual_function,omitempty"`
	PXE             *PXE             `json:"pxe,omitempty"`
	Nat             *Nat             `json:"-"`
	VIP             *VirtualIP       `json:"-"`
	Metering        *MeteringParams  `json:"metering,omitempty"`
}

type VirtualFunction struct {
	Name string `json:"name"`
}

type InterfaceList struct {
	TypeMeta          `json:",inline"`
	InterfaceListMeta `json:"metadata"`
	Status            Status      `json:"status"`
	Items             []Interface `json:"items"`
}

type InterfaceListMeta struct {
}

func (l *InterfaceList) GetItems() []Object {
	res := make([]Object, len(l.Items))
	for i := range l.Items {
		res[i] = &l.Items[i]
	}
	return res
}

func (m *InterfaceList) GetStatus() Status {
	return m.Status
}

// NAT section
type Nat struct {
	TypeMeta `json:",inline"`
	NatMeta  `json:"metadata"`
	Spec     NatSpec `json:"spec"`
	Status   Status  `json:"status"`
}

type NatMeta struct {
	InterfaceID string `json:"interface_id,omitempty"`
}

func (m *NatMeta) GetName() string {
	return m.InterfaceID
}

func (m *Nat) GetStatus() Status {
	return m.Status
}

func (m *Nat) String() string {
	return fmt.Sprintf("%s <%d, %d>", m.Spec.NatIP, m.Spec.MinPort, m.Spec.MaxPort)
}

type NatSpec struct {
	NatIP         *netip.Addr `json:"nat_ip,omitempty"`
	MinPort       uint32      `json:"min_port"`
	MaxPort       uint32      `json:"max_port"`
	UnderlayRoute *netip.Addr `json:"underlay_route,omitempty"`
	Vni           uint32      `json:"vni"`
}

type NatList struct {
	TypeMeta    `json:",inline"`
	NatListMeta `json:"metadata"`
	Status      Status `json:"status"`
	Items       []Nat  `json:"items"`
}

type NatListMeta struct {
	NatIP   *netip.Addr `json:"nat_ip,omitempty"`
	NatType string      `json:"nat_type,omitempty"`
}

func (l *NatList) GetItems() []Object {
	res := make([]Object, len(l.Items))
	for i := range l.Items {
		res[i] = &l.Items[i]
	}
	return res
}

func (m *NatList) GetStatus() Status {
	return m.Status
}

type NeighborNat struct {
	TypeMeta        `json:",inline"`
	NeighborNatMeta `json:"metadata"`
	Spec            NeighborNatSpec `json:"spec"`
	Status          Status          `json:"status"`
}

type NeighborNatMeta struct {
	NatIP *netip.Addr `json:"nat_ip"`
}

func (m *NeighborNatMeta) GetName() string {
	return m.NatIP.String()
}

func (m *NeighborNat) GetStatus() Status {
	return m.Status
}

type NeighborNatSpec struct {
	Vni           uint32      `json:"vni"`
	MinPort       uint32      `json:"min_port"`
	MaxPort       uint32      `json:"max_port"`
	UnderlayRoute *netip.Addr `json:"underlay_route,omitempty"`
}

// FirewallRule section
type FirewallRule struct {
	TypeMeta         `json:",inline"`
	FirewallRuleMeta `json:"metadata"`
	Spec             FirewallRuleSpec `json:"spec"`
	Status           Status           `json:"status"`
}

type FirewallRuleMeta struct {
	InterfaceID string `json:"interface_id"`
}

func (m *FirewallRule) GetName() string {
	return m.FirewallRuleMeta.InterfaceID + "/" + m.Spec.RuleID
}

func (m *FirewallRule) GetStatus() Status {
	return m.Status
}

type FirewallRuleSpec struct {
	RuleID            string                `json:"id"`
	TrafficDirection  string                `json:"direction,omitempty"`
	FirewallAction    string                `json:"action,omitempty"`
	Priority          uint32                `json:"priority"`
	SourcePrefix      *netip.Prefix         `json:"source_prefix,omitempty"`
	DestinationPrefix *netip.Prefix         `json:"destination_prefix,omitempty"`
	ProtocolFilter    *proto.ProtocolFilter `json:"protocol_filter,omitempty"`
}

type FirewallRuleList struct {
	TypeMeta             `json:",inline"`
	FirewallRuleListMeta `json:"metadata"`
	Status               Status         `json:"status"`
	Items                []FirewallRule `json:"items"`
}

type FirewallRuleListMeta struct {
	InterfaceID string `json:"interface_id"`
}

func (l *FirewallRuleList) GetItems() []Object {
	res := make([]Object, len(l.Items))
	for i := range l.Items {
		res[i] = &l.Items[i]
	}
	return res
}

func (m *FirewallRuleList) GetStatus() Status {
	return m.Status
}

// Initialized section
type Initialized struct {
	TypeMeta        `json:",inline"`
	InitializedMeta `json:"metadata"`
	Spec            InitializedSpec `json:"spec"`
	Status          Status          `json:"status"`
}

type InitializedMeta struct {
}

type InitializedSpec struct {
	UUID string `json:"uuid"`
}

func (m *InitializedMeta) GetName() string {
	return "initialized"
}

func (m *Initialized) GetStatus() Status {
	return m.Status
}

// VNI section
type Vni struct {
	TypeMeta `json:",inline"`
	VniMeta  `json:"metadata"`
	Spec     VniSpec `json:"spec"`
	Status   Status  `json:"status"`
}

type VniMeta struct {
	VNI     uint32 `json:"vni"`
	VniType uint8  `json:"vni_type"`
}

type VniSpec struct {
	InUse bool `json:"in_use"`
}

func (m *VniMeta) GetName() string {
	return fmt.Sprintf("%d", m.VNI)
}

func (m *Vni) GetStatus() Status {
	return m.Status
}

// Version section
type Version struct {
	TypeMeta    `json:",inline"`
	VersionMeta `json:"metadata"`
	Spec        VersionSpec `json:"spec"`
	Status      Status      `json:"status"`
}

type VersionMeta struct {
	ClientProtocol string `json:"client_protocol"`
	ClientName     string `json:"client_name"`
	ClientVersion  string `json:"client_version"`
}

type VersionSpec struct {
	ServiceProtocol string `json:"service_protocol"`
	ServiceVersion  string `json:"service_version"`
}

func (m *VersionMeta) GetName() string {
	return fmt.Sprintf("%s-%s", m.ClientName, m.ClientProtocol)
}

func (m *Version) GetStatus() Status {
	return m.Status
}

type CaptureConfig struct {
	SinkNodeIP *netip.Addr `json:"sink_node_ipv6,omitempty"`
	UdpSrcPort uint32      `json:"udp_src_port,omitempty"`
	UdpDstPort uint32      `json:"udp_dst_port,omitempty"`
}

type CaptureStart struct {
	TypeMeta         `json:",inline"`
	CaptureStartMeta `json:"metadata"`
	Spec             CaptureStartSpec `json:"spec"`
	Status           Status           `json:"status"`
}

type CaptureStartMeta struct {
	Config *CaptureConfig `json:"capture_config"`
}

type CaptureStartSpec struct {
	Interfaces []CaptureInterface `json:"interfaces,omitempty"`
}

func (m *CaptureStartMeta) GetName() string {
	return m.Config.SinkNodeIP.String()
}

func (m *CaptureStart) GetStatus() Status {
	return m.Status
}

type CaptureInterface struct {
	InterfaceType string `json:"interface_type"`
	InterfaceInfo string `json:"interface_info"`
}

type CaptureStop struct {
	TypeMeta        `json:",inline"`
	CaptureStopMeta `json:"metadata"`
	Spec            CaptureStopSpec `json:"spec"`
	Status          Status          `json:"status"`
}

type CaptureStopMeta struct {
}

type CaptureStopSpec struct {
	InterfaceCount uint32 `json:"iface_cnt"`
}

func (m *CaptureStopMeta) GetName() string {
	return "capture stopped"
}

func (m *CaptureStop) GetStatus() Status {
	return m.Status
}

type CaptureStatus struct {
	TypeMeta          `json:",inline"`
	CaptureStatusMeta `json:"metadata"`
	Spec              CaptureGetStatusSpec `json:"spec"`
	Status            Status               `json:"status"`
}

type CaptureStatusMeta struct {
}

func (m *CaptureStatusMeta) GetName() string {
	return "get capture status"
}

func (m *CaptureStatus) GetStatus() Status {
	return m.Status
}

type CaptureGetStatusSpec struct {
	OperationStatus bool               `json:"operation_status"`
	Config          CaptureConfig      `json:"capture_config"`
	Interfaces      []CaptureInterface `json:"interfaces,omitempty"`
}

var (
	InterfaceKind              = reflect.TypeOf(Interface{}).Name()
	InterfaceListKind          = reflect.TypeOf(InterfaceList{}).Name()
	LoadBalancerKind           = reflect.TypeOf(LoadBalancer{}).Name()
	LoadBalancerTargetKind     = reflect.TypeOf(LoadBalancerTarget{}).Name()
	LoadBalancerTargetListKind = reflect.TypeOf(LoadBalancerTargetList{}).Name()
	LoadBalancerPrefixKind     = reflect.TypeOf(LoadBalancerPrefix{}).Name()
	PrefixKind                 = reflect.TypeOf(Prefix{}).Name()
	PrefixListKind             = reflect.TypeOf(PrefixList{}).Name()
	VirtualIPKind              = reflect.TypeOf(VirtualIP{}).Name()
	RouteKind                  = reflect.TypeOf(Route{}).Name()
	RouteListKind              = reflect.TypeOf(RouteList{}).Name()
	NatKind                    = reflect.TypeOf(Nat{}).Name()
	NatListKind                = reflect.TypeOf(NatList{}).Name()
	NeighborNatKind            = reflect.TypeOf(NeighborNat{}).Name()
	FirewallRuleKind           = reflect.TypeOf(FirewallRule{}).Name()
	FirewallRuleListKind       = reflect.TypeOf(FirewallRuleList{}).Name()
	InitializedKind            = reflect.TypeOf(Initialized{}).Name()
	VniKind                    = reflect.TypeOf(Vni{}).Name()
	VersionKind                = reflect.TypeOf(Version{}).Name()
	CaptureStartKind           = reflect.TypeOf(CaptureStart{}).Name()
	CaptureStopKind            = reflect.TypeOf(CaptureStop{}).Name()
	CaptureStatusKind          = reflect.TypeOf(CaptureStatus{}).Name()
)
