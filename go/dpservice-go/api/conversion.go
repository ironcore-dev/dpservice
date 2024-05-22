// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	proto "github.com/ironcore-dev/dpservice-go/proto"
)

func ProtoLoadBalancerToLoadBalancer(dpdkLB *proto.GetLoadBalancerResponse, lbID string) (*LoadBalancer, error) {

	var underlayRoute netip.Addr
	if underlayRouteString := string(dpdkLB.GetUnderlayRoute()); underlayRouteString != "" {
		var err error
		underlayRoute, err = netip.ParseAddr(string(dpdkLB.GetUnderlayRoute()))
		if err != nil {
			return nil, fmt.Errorf("error parsing underlay ip: %w", err)
		}
	}
	var lbip netip.Addr
	if lbipString := string(dpdkLB.GetLoadbalancedIp().GetAddress()); lbipString != "" {
		var err error
		lbip, err = netip.ParseAddr(string(dpdkLB.GetLoadbalancedIp().GetAddress()))
		if err != nil {
			return nil, fmt.Errorf("error parsing lb ip: %w", err)
		}
	}
	var lbports = make([]LBPort, 0, len(dpdkLB.LoadbalancedPorts))
	var p LBPort
	for _, lbport := range dpdkLB.LoadbalancedPorts {
		p.Protocol = uint32(lbport.Protocol)
		p.Port = lbport.Port
		lbports = append(lbports, p)
	}

	return &LoadBalancer{
		TypeMeta: TypeMeta{
			Kind: LoadBalancerKind,
		},
		LoadBalancerMeta: LoadBalancerMeta{
			ID: lbID,
		},
		Spec: LoadBalancerSpec{
			VNI:           dpdkLB.Vni,
			LbVipIP:       &lbip,
			Lbports:       lbports,
			UnderlayRoute: &underlayRoute,
		},
		Status: Status{
			Code:    dpdkLB.Status.Code,
			Message: dpdkLB.Status.Message,
		},
	}, nil
}

func StringLbportToLbport(lbport string) (LBPort, error) {
	p := strings.Split(lbport, "/")
	protocolName := strings.ToLower(p[0])
	switch protocolName {
	case "icmp", "tcp", "udp", "sctp":
		protocolName = strings.ToUpper(protocolName)
	case "icmpv6":
		protocolName = "ICMPv6"
	default:
		return LBPort{}, fmt.Errorf("unsupported protocol")
	}
	protocol := proto.Protocol_value[protocolName]
	port, err := strconv.Atoi(p[1])
	if err != nil {
		return LBPort{}, fmt.Errorf("error parsing port number: %w", err)
	}
	return LBPort{Protocol: uint32(protocol), Port: uint32(port)}, nil
}

func ProtoInterfaceToInterface(dpdkIface *proto.Interface) (*Interface, error) {
	var underlayRoute netip.Addr
	if underlayRouteString := string(dpdkIface.GetUnderlayRoute()); underlayRouteString != "" {
		var err error
		underlayRoute, err = netip.ParseAddr(string(dpdkIface.GetUnderlayRoute()))
		if err != nil {
			return nil, fmt.Errorf("error parsing underlay ip: %w", err)
		}
	}

	primaryIpv4, err := netip.ParseAddr(string(dpdkIface.GetPrimaryIpv4()))
	if err != nil {
		return nil, fmt.Errorf("error parsing primary ipv4: %w", err)
	}

	primaryIpv6, err := netip.ParseAddr(string(dpdkIface.GetPrimaryIpv6()))
	if err != nil {
		return nil, fmt.Errorf("error parsing primary ipv6: %w", err)
	}

	return &Interface{
		TypeMeta: TypeMeta{
			Kind: InterfaceKind,
		},
		InterfaceMeta: InterfaceMeta{
			ID: string(dpdkIface.Id),
		},
		Spec: InterfaceSpec{
			VNI:           dpdkIface.GetVni(),
			Device:        dpdkIface.GetPciName(),
			IPv4:          &primaryIpv4,
			IPv6:          &primaryIpv6,
			UnderlayRoute: &underlayRoute,
			Metering:      ProtoMeteringParamsToInterfaceMeteringParams(dpdkIface.GetMeteringParams()),
		},
	}, nil
}

func NetIPAddrToProtoIpAddress(addr *netip.Addr) *proto.IpAddress {
	if addr == nil {
		return nil
	}

	var ipver uint8
	switch {
	case addr.Is4():
		ipver = 0
	case addr.Is6():
		ipver = 1
	}
	return &proto.IpAddress{
		Ipver:   proto.IpVersion(ipver),
		Address: []byte(addr.String()),
	}
}

func ProtoIpAddressToNetIPAddr(protoIP *proto.IpAddress) (*netip.Addr, error) {
	ip, err := netip.ParseAddr(string(protoIP.GetAddress()))
	if err != nil {
		return nil, fmt.Errorf("error parsing IP address: %w", err)
	}
	return &ip, nil
}

func NetIPAddrToProtoIPVersion(addr *netip.Addr) proto.IpVersion {
	switch {
	case addr.Is4():
		return proto.IpVersion_IPV4
	case addr.Is6():
		return proto.IpVersion_IPV6
	default:
		return 0
	}
}

func NetIPAddrToProtoIPConfig(addr *netip.Addr) *proto.IpConfig {
	if addr == nil || !addr.IsValid() {
		return nil
	}

	return &proto.IpConfig{
		PrimaryAddress: []byte(addr.String()),
	}
}

func ProtoVirtualIPToVirtualIP(interfaceID string, dpdkVIP *proto.GetVipResponse) (*VirtualIP, error) {
	ip, err := netip.ParseAddr(string(dpdkVIP.GetVipIp().GetAddress()))
	if err != nil {
		return nil, fmt.Errorf("error parsing virtual ip address: %w", err)
	}

	underlayRoute, err := netip.ParseAddr(string(dpdkVIP.GetUnderlayRoute()))
	if err != nil {
		return nil, fmt.Errorf("error parsing underlay route: %w", err)
	}

	return &VirtualIP{
		TypeMeta: TypeMeta{
			Kind: VirtualIPKind,
		},
		VirtualIPMeta: VirtualIPMeta{
			InterfaceID: interfaceID,
		},
		Spec: VirtualIPSpec{
			IP:            &ip,
			UnderlayRoute: &underlayRoute,
		},
		Status: ProtoStatusToStatus(dpdkVIP.Status),
	}, nil
}

func ProtoPrefixToPrefix(interfaceID string, dpdkPrefix *proto.Prefix) (*Prefix, error) {
	addr, err := netip.ParseAddr(string(dpdkPrefix.GetIp().Address))
	if err != nil {
		return nil, fmt.Errorf("error parsing dpdk prefix address: %w", err)
	}

	prefix := netip.PrefixFrom(addr, int(dpdkPrefix.GetLength()))

	underlayRoute, err := netip.ParseAddr(string(dpdkPrefix.UnderlayRoute))
	if err != nil {
		return nil, fmt.Errorf("error parsing underlay route: %w", err)
	}

	return &Prefix{
		TypeMeta: TypeMeta{
			Kind: PrefixKind,
		},
		PrefixMeta: PrefixMeta{
			InterfaceID: interfaceID,
		},
		Spec: PrefixSpec{
			Prefix:        prefix,
			UnderlayRoute: &underlayRoute,
		},
	}, nil
}

func ProtoRouteToRoute(vni uint32, dpdkRoute *proto.Route) (*Route, error) {
	prefixAddr, err := netip.ParseAddr(string(dpdkRoute.GetPrefix().Ip.GetAddress()))
	if err != nil {
		return nil, fmt.Errorf("error parsing prefix address: %w", err)
	}

	prefix := netip.PrefixFrom(prefixAddr, int(dpdkRoute.GetPrefix().GetLength()))

	nextHopIP, err := netip.ParseAddr(string(dpdkRoute.NexthopAddress.GetAddress()))
	if err != nil {
		return nil, fmt.Errorf("error parsing netxt hop address: %w", err)
	}

	return &Route{
		TypeMeta: TypeMeta{
			RouteKind,
		},
		RouteMeta: RouteMeta{
			VNI: vni,
		},
		Spec: RouteSpec{Prefix: &prefix,
			NextHop: &RouteNextHop{
				VNI: dpdkRoute.GetNexthopVni(),
				IP:  &nextHopIP,
			}},
	}, nil
}

func ProtoLBPrefixToProtoPrefix(lbprefix *proto.Prefix) *proto.Prefix {
	return &proto.Prefix{
		Ip:            lbprefix.Ip,
		Length:        lbprefix.Length,
		UnderlayRoute: lbprefix.UnderlayRoute,
	}
}

func ProtoNatToNat(dpdkNat *proto.GetNatResponse, interfaceID string) (*Nat, error) {
	var underlayRoute netip.Addr
	if underlayRouteString := string(dpdkNat.GetUnderlayRoute()); underlayRouteString != "" {
		var err error
		underlayRoute, err = netip.ParseAddr(string(dpdkNat.GetUnderlayRoute()))
		if err != nil {
			return nil, fmt.Errorf("error parsing underlay ip: %w", err)
		}
	}
	var natip netip.Addr
	if natvipipString := string(dpdkNat.GetNatIp().GetAddress()); natvipipString != "" {
		var err error
		natip, err = netip.ParseAddr(string(dpdkNat.GetNatIp().GetAddress()))
		if err != nil {
			return nil, fmt.Errorf("error parsing nat ip: %w", err)
		}
	}

	return &Nat{
		TypeMeta: TypeMeta{
			Kind: NatKind,
		},
		NatMeta: NatMeta{
			InterfaceID: interfaceID,
		},
		Spec: NatSpec{
			NatIP:         &natip,
			MinPort:       dpdkNat.MinPort,
			MaxPort:       dpdkNat.MaxPort,
			UnderlayRoute: &underlayRoute,
		},
		Status: Status{
			Code:    dpdkNat.Status.Code,
			Message: dpdkNat.Status.Message,
		},
	}, nil
}

func ProtoFwRuleToFwRule(dpdkFwRule *proto.FirewallRule, interfaceID string) (*FirewallRule, error) {

	srcPrefix, err := netip.ParsePrefix(string(dpdkFwRule.GetSourcePrefix().GetIp().GetAddress()) + "/" + strconv.Itoa(int(dpdkFwRule.SourcePrefix.Length)))
	if err != nil {
		return nil, fmt.Errorf("error converting prefix: %w", err)
	}

	dstPrefix, err := netip.ParsePrefix(string(dpdkFwRule.GetDestinationPrefix().GetIp().GetAddress()) + "/" + strconv.Itoa(int(dpdkFwRule.DestinationPrefix.Length)))
	if err != nil {
		return nil, fmt.Errorf("error converting prefix: %w", err)
	}
	var direction, action string
	if dpdkFwRule.Direction == 0 {
		direction = "Ingress"
	} else {
		direction = "Egress"
	}
	if dpdkFwRule.Action == 0 {
		action = "Drop"
	} else {
		action = "Accept"
	}

	return &FirewallRule{
		TypeMeta: TypeMeta{Kind: FirewallRuleKind},
		FirewallRuleMeta: FirewallRuleMeta{
			InterfaceID: interfaceID,
		},
		Spec: FirewallRuleSpec{
			RuleID:            string(dpdkFwRule.Id),
			TrafficDirection:  direction,
			FirewallAction:    action,
			Priority:          dpdkFwRule.Priority,
			SourcePrefix:      &srcPrefix,
			DestinationPrefix: &dstPrefix,
			ProtocolFilter:    dpdkFwRule.ProtocolFilter,
		},
	}, nil
}

func ProtoStatusToStatus(dpdkStatus *proto.Status) Status {
	if dpdkStatus == nil {
		return Status{
			Code:    0,
			Message: "",
		}
	}
	return Status{
		Code:    dpdkStatus.Code,
		Message: dpdkStatus.Message,
	}
}

func CaptureIfaceTypeToProtoIfaceType(interfaceType string) (proto.CaptureInterfaceType, error) {
	switch interfaceType {
	case "pf":
		return proto.CaptureInterfaceType_SINGLE_PF, nil
	case "vf":
		return proto.CaptureInterfaceType_SINGLE_VF, nil
	default:
		return 0, fmt.Errorf("unsupported interface type")
	}
}

func ProtoIfaceTypeToCaptureIfaceType(interfaceType proto.CaptureInterfaceType) (string, error) {
	switch interfaceType {
	case proto.CaptureInterfaceType_SINGLE_PF:
		return "pf", nil
	case proto.CaptureInterfaceType_SINGLE_VF:
		return "vf", nil
	default:
		return "", fmt.Errorf("unsupported interface type")
	}
}

func FillCaptureIfaceInfo(interfaceInfo string, request *proto.CapturedInterface) error {
	switch request.InterfaceType {
	case proto.CaptureInterfaceType_SINGLE_PF:
		pf_index, err := strconv.Atoi(interfaceInfo)
		if err != nil {
			return fmt.Errorf("error parsing pf index: %w", err)
		}
		request.Spec = &proto.CapturedInterface_PfIndex{PfIndex: uint32(pf_index)}
	case proto.CaptureInterfaceType_SINGLE_VF:
		request.Spec = &proto.CapturedInterface_VfName{VfName: []byte(interfaceInfo)}
	}
	return nil
}

func ProtoIfaceInfoToCaptureIfaceInfo(request *proto.CapturedInterface) (string, error) {
	switch request.InterfaceType {
	case proto.CaptureInterfaceType_SINGLE_PF:
		return strconv.Itoa(int(request.GetPfIndex())), nil
	case proto.CaptureInterfaceType_SINGLE_VF:
		return string(request.GetVfName()), nil
	default:
		return "", fmt.Errorf("unsupported interface type")
	}
}

func InterfaceMeteringParamsToProtoMeteringParams(meteringParams *MeteringParams) *proto.MeteringParams {

	if meteringParams == nil {
		return &proto.MeteringParams{
			TotalRate:  0,
			PublicRate: 0,
		}
	}

	return &proto.MeteringParams{
		TotalRate:  meteringParams.TotalRate,
		PublicRate: meteringParams.PublicRate,
	}
}

func ProtoMeteringParamsToInterfaceMeteringParams(meteringParams *proto.MeteringParams) *MeteringParams {

	return &MeteringParams{
		TotalRate:  meteringParams.TotalRate,
		PublicRate: meteringParams.PublicRate,
	}
}
