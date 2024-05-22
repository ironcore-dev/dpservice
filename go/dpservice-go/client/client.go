// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/ironcore-dev/dpservice-go/api"
	"github.com/ironcore-dev/dpservice-go/errors"
	dpdkproto "github.com/ironcore-dev/dpservice-go/proto"
)

type Client interface {
	GetLoadBalancer(ctx context.Context, id string, ignoredErrors ...[]uint32) (*api.LoadBalancer, error)
	CreateLoadBalancer(ctx context.Context, lb *api.LoadBalancer, ignoredErrors ...[]uint32) (*api.LoadBalancer, error)
	DeleteLoadBalancer(ctx context.Context, id string, ignoredErrors ...[]uint32) (*api.LoadBalancer, error)

	ListLoadBalancerPrefixes(ctx context.Context, interfaceID string, ignoredErrors ...[]uint32) (*api.PrefixList, error)
	CreateLoadBalancerPrefix(ctx context.Context, prefix *api.LoadBalancerPrefix, ignoredErrors ...[]uint32) (*api.LoadBalancerPrefix, error)
	DeleteLoadBalancerPrefix(ctx context.Context, interfaceID string, prefix *netip.Prefix, ignoredErrors ...[]uint32) (*api.LoadBalancerPrefix, error)

	ListLoadBalancerTargets(ctx context.Context, interfaceID string, ignoredErrors ...[]uint32) (*api.LoadBalancerTargetList, error)
	CreateLoadBalancerTarget(ctx context.Context, lbtarget *api.LoadBalancerTarget, ignoredErrors ...[]uint32) (*api.LoadBalancerTarget, error)
	DeleteLoadBalancerTarget(ctx context.Context, id string, targetIP *netip.Addr, ignoredErrors ...[]uint32) (*api.LoadBalancerTarget, error)

	GetInterface(ctx context.Context, id string, ignoredErrors ...[]uint32) (*api.Interface, error)
	ListInterfaces(ctx context.Context, ignoredErrors ...[]uint32) (*api.InterfaceList, error)
	CreateInterface(ctx context.Context, iface *api.Interface, ignoredErrors ...[]uint32) (*api.Interface, error)
	DeleteInterface(ctx context.Context, id string, ignoredErrors ...[]uint32) (*api.Interface, error)

	GetVirtualIP(ctx context.Context, interfaceID string, ignoredErrors ...[]uint32) (*api.VirtualIP, error)
	CreateVirtualIP(ctx context.Context, virtualIP *api.VirtualIP, ignoredErrors ...[]uint32) (*api.VirtualIP, error)
	DeleteVirtualIP(ctx context.Context, interfaceID string, ignoredErrors ...[]uint32) (*api.VirtualIP, error)

	ListPrefixes(ctx context.Context, interfaceID string, ignoredErrors ...[]uint32) (*api.PrefixList, error)
	CreatePrefix(ctx context.Context, prefix *api.Prefix, ignoredErrors ...[]uint32) (*api.Prefix, error)
	DeletePrefix(ctx context.Context, interfaceID string, prefix *netip.Prefix, ignoredErrors ...[]uint32) (*api.Prefix, error)

	ListRoutes(ctx context.Context, vni uint32, ignoredErrors ...[]uint32) (*api.RouteList, error)
	CreateRoute(ctx context.Context, route *api.Route, ignoredErrors ...[]uint32) (*api.Route, error)
	DeleteRoute(ctx context.Context, vni uint32, prefix *netip.Prefix, ignoredErrors ...[]uint32) (*api.Route, error)

	GetNat(ctx context.Context, interfaceID string, ignoredErrors ...[]uint32) (*api.Nat, error)
	CreateNat(ctx context.Context, nat *api.Nat, ignoredErrors ...[]uint32) (*api.Nat, error)
	DeleteNat(ctx context.Context, interfaceID string, ignoredErrors ...[]uint32) (*api.Nat, error)
	ListLocalNats(ctx context.Context, natIP *netip.Addr, ignoredErrors ...[]uint32) (*api.NatList, error)

	CreateNeighborNat(ctx context.Context, nat *api.NeighborNat, ignoredErrors ...[]uint32) (*api.NeighborNat, error)
	ListNats(ctx context.Context, natIP *netip.Addr, natType string, ignoredErrors ...[]uint32) (*api.NatList, error)
	DeleteNeighborNat(ctx context.Context, neigbhorNat *api.NeighborNat, ignoredErrors ...[]uint32) (*api.NeighborNat, error)
	ListNeighborNats(ctx context.Context, natIP *netip.Addr, ignoredErrors ...[]uint32) (*api.NatList, error)

	ListFirewallRules(ctx context.Context, interfaceID string, ignoredErrors ...[]uint32) (*api.FirewallRuleList, error)
	CreateFirewallRule(ctx context.Context, fwRule *api.FirewallRule, ignoredErrors ...[]uint32) (*api.FirewallRule, error)
	GetFirewallRule(ctx context.Context, interfaceID string, ruleID string, ignoredErrors ...[]uint32) (*api.FirewallRule, error)
	DeleteFirewallRule(ctx context.Context, interfaceID string, ruleID string, ignoredErrors ...[]uint32) (*api.FirewallRule, error)

	CheckInitialized(ctx context.Context, ignoredErrors ...[]uint32) (*api.Initialized, error)
	Initialize(ctx context.Context, ignoredErrors ...[]uint32) (*api.Initialized, error)
	GetVni(ctx context.Context, vni uint32, vniType uint8, ignoredErrors ...[]uint32) (*api.Vni, error)
	ResetVni(ctx context.Context, vni uint32, vniType uint8, ignoredErrors ...[]uint32) (*api.Vni, error)
	GetVersion(ctx context.Context, version *api.Version, ignoredErrors ...[]uint32) (*api.Version, error)

	CaptureStart(ctx context.Context, capture *api.CaptureStart, ignoredErrors ...[]uint32) (*api.CaptureStart, error)
	CaptureStop(ctx context.Context, ignoredErrors ...[]uint32) (*api.CaptureStop, error)
	CaptureStatus(ctx context.Context, ignoredErrors ...[]uint32) (*api.CaptureStatus, error)
}

type client struct {
	dpdkproto.DPDKironcoreClient
}

func NewClient(protoClient dpdkproto.DPDKironcoreClient) Client {
	return &client{protoClient}
}

func (c *client) GetLoadBalancer(ctx context.Context, id string, ignoredErrors ...[]uint32) (*api.LoadBalancer, error) {
	res, err := c.DPDKironcoreClient.GetLoadBalancer(ctx, &dpdkproto.GetLoadBalancerRequest{
		LoadbalancerId: []byte(id),
	})
	if err != nil {
		return &api.LoadBalancer{}, err
	}
	retLoadBalancer := &api.LoadBalancer{
		TypeMeta:         api.TypeMeta{Kind: api.LoadBalancerKind},
		LoadBalancerMeta: api.LoadBalancerMeta{ID: id},
		Status:           api.ProtoStatusToStatus(res.Status),
	}
	if res.GetStatus().GetCode() != 0 {
		return retLoadBalancer, errors.GetError(res.Status, ignoredErrors)
	}
	return api.ProtoLoadBalancerToLoadBalancer(res, id)
}

func (c *client) CreateLoadBalancer(ctx context.Context, lb *api.LoadBalancer, ignoredErrors ...[]uint32) (*api.LoadBalancer, error) {
	var lbPorts = make([]*dpdkproto.LbPort, 0, len(lb.Spec.Lbports))
	for _, p := range lb.Spec.Lbports {
		lbPort := &dpdkproto.LbPort{Port: p.Port, Protocol: dpdkproto.Protocol(p.Protocol)}
		lbPorts = append(lbPorts, lbPort)
	}
	res, err := c.DPDKironcoreClient.CreateLoadBalancer(ctx, &dpdkproto.CreateLoadBalancerRequest{
		LoadbalancerId:    []byte(lb.LoadBalancerMeta.ID),
		Vni:               lb.Spec.VNI,
		LoadbalancedIp:    api.NetIPAddrToProtoIpAddress(lb.Spec.LbVipIP),
		LoadbalancedPorts: lbPorts,
	})
	if err != nil {
		return &api.LoadBalancer{}, err
	}
	retLoadBalancer := &api.LoadBalancer{
		TypeMeta:         api.TypeMeta{Kind: api.LoadBalancerKind},
		LoadBalancerMeta: lb.LoadBalancerMeta,
		Status:           api.ProtoStatusToStatus(res.Status),
	}
	if res.GetStatus().GetCode() != 0 {
		return retLoadBalancer, errors.GetError(res.Status, ignoredErrors)
	}

	underlayRoute, err := netip.ParseAddr(string(res.GetUnderlayRoute()))
	if err != nil {
		return retLoadBalancer, fmt.Errorf("error parsing underlay route: %w", err)
	}
	retLoadBalancer.Spec = lb.Spec
	retLoadBalancer.Spec.UnderlayRoute = &underlayRoute

	return retLoadBalancer, nil
}

func (c *client) DeleteLoadBalancer(ctx context.Context, id string, ignoredErrors ...[]uint32) (*api.LoadBalancer, error) {
	res, err := c.DPDKironcoreClient.DeleteLoadBalancer(ctx, &dpdkproto.DeleteLoadBalancerRequest{
		LoadbalancerId: []byte(id),
	})
	if err != nil {
		return &api.LoadBalancer{}, err
	}
	retLoadBalancer := &api.LoadBalancer{
		TypeMeta:         api.TypeMeta{Kind: api.LoadBalancerKind},
		LoadBalancerMeta: api.LoadBalancerMeta{ID: id},
		Status:           api.ProtoStatusToStatus(res.Status),
	}
	if res.GetStatus().GetCode() != 0 {
		return retLoadBalancer, errors.GetError(res.Status, ignoredErrors)
	}
	return retLoadBalancer, nil
}

func (c *client) ListLoadBalancerPrefixes(ctx context.Context, interfaceID string, ignoredErrors ...[]uint32) (*api.PrefixList, error) {
	res, err := c.DPDKironcoreClient.ListLoadBalancerPrefixes(ctx, &dpdkproto.ListLoadBalancerPrefixesRequest{
		InterfaceId: []byte(interfaceID),
	})
	if err != nil {
		return nil, err
	}

	prefixes := make([]api.Prefix, len(res.GetPrefixes()))
	for i, dpdkPrefix := range res.GetPrefixes() {
		prefix, err := api.ProtoPrefixToPrefix(interfaceID, dpdkPrefix)
		if err != nil {
			return nil, err
		}
		prefix.Kind = api.LoadBalancerPrefixKind

		prefixes[i] = *prefix
	}

	return &api.PrefixList{
		TypeMeta:       api.TypeMeta{Kind: "LoadBalancerPrefixList"},
		PrefixListMeta: api.PrefixListMeta{InterfaceID: interfaceID},
		Items:          prefixes,
		Status:         api.ProtoStatusToStatus(res.Status),
	}, nil
}

func (c *client) CreateLoadBalancerPrefix(ctx context.Context, lbprefix *api.LoadBalancerPrefix, ignoredErrors ...[]uint32) (*api.LoadBalancerPrefix, error) {
	lbPrefixAddr := lbprefix.Spec.Prefix.Addr()
	res, err := c.DPDKironcoreClient.CreateLoadBalancerPrefix(ctx, &dpdkproto.CreateLoadBalancerPrefixRequest{
		InterfaceId: []byte(lbprefix.InterfaceID),
		Prefix: &dpdkproto.Prefix{
			Ip:     api.NetIPAddrToProtoIpAddress(&lbPrefixAddr),
			Length: uint32(lbprefix.Spec.Prefix.Bits()),
		},
	})
	if err != nil {
		return &api.LoadBalancerPrefix{}, err
	}
	retLBPrefix := &api.LoadBalancerPrefix{
		TypeMeta:               api.TypeMeta{Kind: api.LoadBalancerPrefixKind},
		LoadBalancerPrefixMeta: lbprefix.LoadBalancerPrefixMeta,
		Spec: api.LoadBalancerPrefixSpec{
			Prefix: lbprefix.Spec.Prefix,
		},
		Status: api.ProtoStatusToStatus(res.Status),
	}
	if res.GetStatus().GetCode() != 0 {
		return retLBPrefix, errors.GetError(res.Status, ignoredErrors)
	}
	underlayRoute, err := netip.ParseAddr(string(res.GetUnderlayRoute()))
	if err != nil {
		return retLBPrefix, fmt.Errorf("error parsing underlay route: %w", err)
	}
	retLBPrefix.Spec.UnderlayRoute = &underlayRoute
	return retLBPrefix, nil
}

func (c *client) DeleteLoadBalancerPrefix(ctx context.Context, interfaceID string, prefix *netip.Prefix, ignoredErrors ...[]uint32) (*api.LoadBalancerPrefix, error) {
	lbPrefixAddr := prefix.Addr()
	res, err := c.DPDKironcoreClient.DeleteLoadBalancerPrefix(ctx, &dpdkproto.DeleteLoadBalancerPrefixRequest{
		InterfaceId: []byte(interfaceID),
		Prefix: &dpdkproto.Prefix{
			Ip:     api.NetIPAddrToProtoIpAddress(&lbPrefixAddr),
			Length: uint32(prefix.Bits()),
		},
	})
	if err != nil {
		return &api.LoadBalancerPrefix{}, err
	}
	retLBPrefix := &api.LoadBalancerPrefix{
		TypeMeta:               api.TypeMeta{Kind: api.LoadBalancerPrefixKind},
		LoadBalancerPrefixMeta: api.LoadBalancerPrefixMeta{InterfaceID: interfaceID},
		Spec:                   api.LoadBalancerPrefixSpec{Prefix: *prefix},
		Status:                 api.ProtoStatusToStatus(res.Status),
	}
	if res.GetStatus().GetCode() != 0 {
		return retLBPrefix, errors.GetError(res.Status, ignoredErrors)
	}
	return retLBPrefix, nil
}

func (c *client) ListLoadBalancerTargets(ctx context.Context, loadBalancerID string, ignoredErrors ...[]uint32) (*api.LoadBalancerTargetList, error) {
	res, err := c.DPDKironcoreClient.ListLoadBalancerTargets(ctx, &dpdkproto.ListLoadBalancerTargetsRequest{
		LoadbalancerId: []byte(loadBalancerID),
	})
	if err != nil {
		return &api.LoadBalancerTargetList{}, err
	}
	if res.GetStatus().GetCode() != 0 {
		return &api.LoadBalancerTargetList{
			TypeMeta: api.TypeMeta{Kind: api.LoadBalancerTargetListKind},
			Status:   api.ProtoStatusToStatus(res.Status)}, errors.GetError(res.Status, ignoredErrors)
	}

	lbtargets := make([]api.LoadBalancerTarget, len(res.GetTargetIps()))
	for i, dpdkLBtarget := range res.GetTargetIps() {
		var lbtarget api.LoadBalancerTarget
		lbtarget.TypeMeta.Kind = api.LoadBalancerTargetKind
		lbtarget.Spec.TargetIP, err = api.ProtoIpAddressToNetIPAddr(dpdkLBtarget)
		if err != nil {
			return nil, err
		}
		lbtarget.LoadBalancerTargetMeta.LoadbalancerID = loadBalancerID

		lbtargets[i] = lbtarget
	}

	return &api.LoadBalancerTargetList{
		TypeMeta:                   api.TypeMeta{Kind: api.LoadBalancerTargetListKind},
		LoadBalancerTargetListMeta: api.LoadBalancerTargetListMeta{LoadBalancerID: loadBalancerID},
		Items:                      lbtargets,
		Status:                     api.ProtoStatusToStatus(res.Status),
	}, nil
}

func (c *client) CreateLoadBalancerTarget(ctx context.Context, lbtarget *api.LoadBalancerTarget, ignoredErrors ...[]uint32) (*api.LoadBalancerTarget, error) {
	res, err := c.DPDKironcoreClient.CreateLoadBalancerTarget(ctx, &dpdkproto.CreateLoadBalancerTargetRequest{
		LoadbalancerId: []byte(lbtarget.LoadBalancerTargetMeta.LoadbalancerID),
		TargetIp:       api.NetIPAddrToProtoIpAddress(lbtarget.Spec.TargetIP),
	})
	if err != nil {
		return &api.LoadBalancerTarget{}, err
	}
	retLBTarget := &api.LoadBalancerTarget{
		TypeMeta:               api.TypeMeta{Kind: api.LoadBalancerTargetKind},
		LoadBalancerTargetMeta: lbtarget.LoadBalancerTargetMeta,
		Status:                 api.ProtoStatusToStatus(res.Status),
	}
	if res.GetStatus().GetCode() != 0 {
		return retLBTarget, errors.GetError(res.Status, ignoredErrors)
	}
	retLBTarget.Spec = lbtarget.Spec
	return retLBTarget, nil
}

func (c *client) DeleteLoadBalancerTarget(ctx context.Context, lbid string, targetIP *netip.Addr, ignoredErrors ...[]uint32) (*api.LoadBalancerTarget, error) {
	res, err := c.DPDKironcoreClient.DeleteLoadBalancerTarget(ctx, &dpdkproto.DeleteLoadBalancerTargetRequest{
		LoadbalancerId: []byte(lbid),
		TargetIp:       api.NetIPAddrToProtoIpAddress(targetIP),
	})
	if err != nil {
		return &api.LoadBalancerTarget{}, err
	}
	retLBTarget := &api.LoadBalancerTarget{
		TypeMeta:               api.TypeMeta{Kind: api.LoadBalancerTargetKind},
		LoadBalancerTargetMeta: api.LoadBalancerTargetMeta{LoadbalancerID: lbid},
		Status:                 api.ProtoStatusToStatus(res.Status),
	}
	if res.Status.GetCode() != 0 {
		return retLBTarget, errors.GetError(res.Status, ignoredErrors)
	}
	return retLBTarget, nil
}

func (c *client) GetInterface(ctx context.Context, id string, ignoredErrors ...[]uint32) (*api.Interface, error) {
	res, err := c.DPDKironcoreClient.GetInterface(ctx, &dpdkproto.GetInterfaceRequest{
		InterfaceId: []byte(id),
	})
	if err != nil {
		return &api.Interface{}, err
	}
	if res.GetStatus().GetCode() != 0 {
		return &api.Interface{
			TypeMeta:      api.TypeMeta{Kind: api.InterfaceKind},
			InterfaceMeta: api.InterfaceMeta{ID: id},
			Status:        api.ProtoStatusToStatus(res.Status)}, errors.GetError(res.Status, ignoredErrors)
	}
	return api.ProtoInterfaceToInterface(res.GetInterface())
}

func (c *client) ListInterfaces(ctx context.Context, ignoredErrors ...[]uint32) (*api.InterfaceList, error) {
	res, err := c.DPDKironcoreClient.ListInterfaces(ctx, &dpdkproto.ListInterfacesRequest{})
	if err != nil {
		return nil, err
	}

	ifaces := make([]api.Interface, len(res.GetInterfaces()))
	for i, dpdkIface := range res.GetInterfaces() {
		iface, err := api.ProtoInterfaceToInterface(dpdkIface)
		if err != nil {
			return nil, err
		}

		ifaces[i] = *iface
	}

	return &api.InterfaceList{
		TypeMeta: api.TypeMeta{Kind: api.InterfaceListKind},
		Items:    ifaces,
		Status:   api.ProtoStatusToStatus(res.Status),
	}, nil
}

func (c *client) CreateInterface(ctx context.Context, iface *api.Interface, ignoredErrors ...[]uint32) (*api.Interface, error) {
	req := dpdkproto.CreateInterfaceRequest{
		InterfaceType:      dpdkproto.InterfaceType_VIRTUAL,
		InterfaceId:        []byte(iface.ID),
		Vni:                iface.Spec.VNI,
		Ipv4Config:         api.NetIPAddrToProtoIPConfig(iface.Spec.IPv4),
		Ipv6Config:         api.NetIPAddrToProtoIPConfig(iface.Spec.IPv6),
		DeviceName:         iface.Spec.Device,
		MeteringParameters: api.InterfaceMeteringParamsToProtoMeteringParams(iface.Spec.Metering),
	}
	if iface.Spec.PXE != nil {
		if iface.Spec.PXE.FileName != "" && iface.Spec.PXE.Server != "" {
			req.PxeConfig = &dpdkproto.PxeConfig{NextServer: iface.Spec.PXE.Server, BootFilename: iface.Spec.PXE.FileName}
		}
	}

	res, err := c.DPDKironcoreClient.CreateInterface(ctx, &req)
	if err != nil {
		return &api.Interface{}, err
	}
	retInterface := &api.Interface{
		TypeMeta:      iface.TypeMeta,
		InterfaceMeta: iface.InterfaceMeta,
		Status:        api.ProtoStatusToStatus(res.Status),
	}
	if res.GetStatus().GetCode() != 0 {
		return retInterface, errors.GetError(res.Status, ignoredErrors)
	}

	underlayRoute, err := netip.ParseAddr(string(res.GetUnderlayRoute()))
	if err != nil {
		return retInterface, fmt.Errorf("error parsing underlay route: %w", err)
	}
	retInterface.Spec = iface.Spec
	retInterface.Spec.UnderlayRoute = &underlayRoute
	retInterface.Spec.VirtualFunction = &api.VirtualFunction{
		Name: res.Vf.Name,
	}

	return retInterface, nil
}

func (c *client) DeleteInterface(ctx context.Context, id string, ignoredErrors ...[]uint32) (*api.Interface, error) {
	res, err := c.DPDKironcoreClient.DeleteInterface(ctx, &dpdkproto.DeleteInterfaceRequest{
		InterfaceId: []byte(id),
	})
	if err != nil {
		return &api.Interface{}, err
	}
	retInterface := &api.Interface{
		TypeMeta:      api.TypeMeta{Kind: api.InterfaceKind},
		InterfaceMeta: api.InterfaceMeta{ID: id},
		Status:        api.ProtoStatusToStatus(res.Status),
	}
	if res.GetStatus().GetCode() != 0 {
		return retInterface, errors.GetError(res.Status, ignoredErrors)
	}
	return retInterface, nil
}

func (c *client) GetVirtualIP(ctx context.Context, interfaceID string, ignoredErrors ...[]uint32) (*api.VirtualIP, error) {
	res, err := c.DPDKironcoreClient.GetVip(ctx, &dpdkproto.GetVipRequest{
		InterfaceId: []byte(interfaceID),
	})
	if err != nil {
		return &api.VirtualIP{}, err
	}
	if res.GetStatus().GetCode() != 0 {
		return &api.VirtualIP{
			TypeMeta:      api.TypeMeta{Kind: api.VirtualIPKind},
			VirtualIPMeta: api.VirtualIPMeta{InterfaceID: interfaceID},
			Status:        api.ProtoStatusToStatus(res.Status)}, errors.GetError(res.Status, ignoredErrors)
	}
	return api.ProtoVirtualIPToVirtualIP(interfaceID, res)
}

func (c *client) CreateVirtualIP(ctx context.Context, virtualIP *api.VirtualIP, ignoredErrors ...[]uint32) (*api.VirtualIP, error) {
	res, err := c.DPDKironcoreClient.CreateVip(ctx, &dpdkproto.CreateVipRequest{
		InterfaceId: []byte(virtualIP.InterfaceID),
		VipIp:       api.NetIPAddrToProtoIpAddress(virtualIP.Spec.IP),
	})
	if err != nil {
		return &api.VirtualIP{}, err
	}
	retVirtualIP := &api.VirtualIP{
		TypeMeta:      api.TypeMeta{Kind: api.VirtualIPKind},
		VirtualIPMeta: virtualIP.VirtualIPMeta,
		Spec: api.VirtualIPSpec{
			IP: virtualIP.Spec.IP,
		},
		Status: api.ProtoStatusToStatus(res.Status),
	}
	if res.GetStatus().GetCode() != 0 {
		return retVirtualIP, errors.GetError(res.Status, ignoredErrors)
	}
	underlayRoute, err := netip.ParseAddr(string(res.GetUnderlayRoute()))
	if err != nil {
		return retVirtualIP, fmt.Errorf("error parsing underlay route: %w", err)
	}
	retVirtualIP.Spec.UnderlayRoute = &underlayRoute
	return retVirtualIP, nil
}

func (c *client) DeleteVirtualIP(ctx context.Context, interfaceID string, ignoredErrors ...[]uint32) (*api.VirtualIP, error) {
	res, err := c.DPDKironcoreClient.DeleteVip(ctx, &dpdkproto.DeleteVipRequest{
		InterfaceId: []byte(interfaceID),
	})
	if err != nil {
		return &api.VirtualIP{}, err
	}
	retVirtualIP := &api.VirtualIP{
		TypeMeta:      api.TypeMeta{Kind: api.VirtualIPKind},
		VirtualIPMeta: api.VirtualIPMeta{InterfaceID: interfaceID},
		Status:        api.ProtoStatusToStatus(res.Status),
	}
	if res.GetStatus().GetCode() != 0 {
		return retVirtualIP, errors.GetError(res.Status, ignoredErrors)
	}
	return retVirtualIP, nil
}

func (c *client) ListPrefixes(ctx context.Context, interfaceID string, ignoredErrors ...[]uint32) (*api.PrefixList, error) {
	res, err := c.DPDKironcoreClient.ListPrefixes(ctx, &dpdkproto.ListPrefixesRequest{
		InterfaceId: []byte(interfaceID),
	})
	if err != nil {
		return nil, err
	}

	prefixes := make([]api.Prefix, len(res.GetPrefixes()))
	for i, dpdkPrefix := range res.GetPrefixes() {
		prefix, err := api.ProtoPrefixToPrefix(interfaceID, dpdkPrefix)
		if err != nil {
			return nil, err
		}

		prefixes[i] = *prefix
	}

	return &api.PrefixList{
		TypeMeta:       api.TypeMeta{Kind: api.PrefixListKind},
		PrefixListMeta: api.PrefixListMeta{InterfaceID: interfaceID},
		Items:          prefixes,
		Status:         api.ProtoStatusToStatus(res.Status),
	}, nil
}

func (c *client) CreatePrefix(ctx context.Context, prefix *api.Prefix, ignoredErrors ...[]uint32) (*api.Prefix, error) {
	prefixAddr := prefix.Spec.Prefix.Addr()
	res, err := c.DPDKironcoreClient.CreatePrefix(ctx, &dpdkproto.CreatePrefixRequest{
		InterfaceId: []byte(prefix.InterfaceID),
		Prefix: &dpdkproto.Prefix{
			Ip:     api.NetIPAddrToProtoIpAddress(&prefixAddr),
			Length: uint32(prefix.Spec.Prefix.Bits()),
		},
	})
	if err != nil {
		return &api.Prefix{}, err
	}
	retPrefix := &api.Prefix{
		TypeMeta:   api.TypeMeta{Kind: api.PrefixKind},
		PrefixMeta: prefix.PrefixMeta,
		Spec:       api.PrefixSpec{Prefix: prefix.Spec.Prefix},
		Status:     api.ProtoStatusToStatus(res.Status),
	}

	if res.GetStatus().GetCode() != 0 {
		return retPrefix, errors.GetError(res.Status, ignoredErrors)
	}
	underlayRoute, err := netip.ParseAddr(string(res.GetUnderlayRoute()))
	if err != nil {
		return retPrefix, fmt.Errorf("error parsing underlay route: %w", err)
	}
	retPrefix.Spec.UnderlayRoute = &underlayRoute
	return retPrefix, nil
}

func (c *client) DeletePrefix(ctx context.Context, interfaceID string, prefix *netip.Prefix, ignoredErrors ...[]uint32) (*api.Prefix, error) {
	prefixAddr := prefix.Addr()
	res, err := c.DPDKironcoreClient.DeletePrefix(ctx, &dpdkproto.DeletePrefixRequest{
		InterfaceId: []byte(interfaceID),
		Prefix: &dpdkproto.Prefix{
			Ip:     api.NetIPAddrToProtoIpAddress(&prefixAddr),
			Length: uint32(prefix.Bits()),
		},
	})
	if err != nil {
		return &api.Prefix{}, err
	}
	retPrefix := &api.Prefix{
		TypeMeta:   api.TypeMeta{Kind: api.PrefixKind},
		PrefixMeta: api.PrefixMeta{InterfaceID: interfaceID},
		Spec:       api.PrefixSpec{Prefix: *prefix},
		Status:     api.ProtoStatusToStatus(res.Status),
	}
	if res.GetStatus().GetCode() != 0 {
		return retPrefix, errors.GetError(res.Status, ignoredErrors)
	}
	return retPrefix, nil
}

func (c *client) CreateRoute(ctx context.Context, route *api.Route, ignoredErrors ...[]uint32) (*api.Route, error) {
	if route.Spec.Prefix == nil {
		return nil, fmt.Errorf("prefix needs to be specified")
	}
	routePrefixAddr := route.Spec.Prefix.Addr()

	if route.Spec.NextHop == nil {
		return nil, fmt.Errorf("nextHop needs to be specified")
	}
	res, err := c.DPDKironcoreClient.CreateRoute(ctx, &dpdkproto.CreateRouteRequest{
		Vni: route.VNI,
		Route: &dpdkproto.Route{
			Weight: 100,
			Prefix: &dpdkproto.Prefix{
				Ip:     api.NetIPAddrToProtoIpAddress(&routePrefixAddr),
				Length: uint32(route.Spec.Prefix.Bits()),
			},
			NexthopVni:     route.Spec.NextHop.VNI,
			NexthopAddress: api.NetIPAddrToProtoIpAddress(route.Spec.NextHop.IP),
		},
	})
	if err != nil {
		return &api.Route{}, err
	}
	retRoute := &api.Route{
		TypeMeta:  api.TypeMeta{Kind: api.RouteKind},
		RouteMeta: route.RouteMeta,
		Spec: api.RouteSpec{
			Prefix:  route.Spec.Prefix,
			NextHop: &api.RouteNextHop{}},
		Status: api.ProtoStatusToStatus(res.Status),
	}
	if res.GetStatus().GetCode() != 0 {
		return retRoute, errors.GetError(res.Status, ignoredErrors)
	}
	retRoute.Spec = route.Spec
	return retRoute, nil
}

func (c *client) DeleteRoute(ctx context.Context, vni uint32, prefix *netip.Prefix, ignoredErrors ...[]uint32) (*api.Route, error) {
	routePrefixAddr := prefix.Addr()
	res, err := c.DPDKironcoreClient.DeleteRoute(ctx, &dpdkproto.DeleteRouteRequest{
		Vni: vni,
		Route: &dpdkproto.Route{
			Weight: 100,
			Prefix: &dpdkproto.Prefix{
				Ip:     api.NetIPAddrToProtoIpAddress(&routePrefixAddr),
				Length: uint32(prefix.Bits()),
			},
		},
	})
	if err != nil {
		return &api.Route{}, err
	}
	retRoute := &api.Route{
		TypeMeta:  api.TypeMeta{Kind: api.RouteKind},
		RouteMeta: api.RouteMeta{VNI: vni},
		Spec: api.RouteSpec{
			Prefix:  prefix,
			NextHop: &api.RouteNextHop{},
		},
		Status: api.ProtoStatusToStatus(res.Status),
	}
	if res.GetStatus().GetCode() != 0 {
		return retRoute, errors.GetError(res.Status, ignoredErrors)
	}
	return retRoute, nil
}

func (c *client) ListRoutes(ctx context.Context, vni uint32, ignoredErrors ...[]uint32) (*api.RouteList, error) {
	res, err := c.DPDKironcoreClient.ListRoutes(ctx, &dpdkproto.ListRoutesRequest{
		Vni: vni,
	})
	if err != nil {
		return nil, err
	}

	routes := make([]api.Route, len(res.GetRoutes()))
	for i, dpdkRoute := range res.GetRoutes() {
		route, err := api.ProtoRouteToRoute(vni, dpdkRoute)
		if err != nil {
			return nil, err
		}

		routes[i] = *route
	}

	return &api.RouteList{
		TypeMeta:      api.TypeMeta{Kind: api.RouteListKind},
		RouteListMeta: api.RouteListMeta{VNI: vni},
		Items:         routes,
		Status:        api.ProtoStatusToStatus(res.Status),
	}, nil
}

func (c *client) GetNat(ctx context.Context, interfaceID string, ignoredErrors ...[]uint32) (*api.Nat, error) {
	res, err := c.DPDKironcoreClient.GetNat(ctx, &dpdkproto.GetNatRequest{InterfaceId: []byte(interfaceID)})
	if err != nil {
		return &api.Nat{}, err
	}
	if res.GetStatus().GetCode() != 0 {
		return &api.Nat{
			TypeMeta: api.TypeMeta{Kind: api.NatKind},
			NatMeta:  api.NatMeta{InterfaceID: interfaceID},
			Status:   api.ProtoStatusToStatus(res.Status)}, errors.GetError(res.Status, ignoredErrors)
	}
	return api.ProtoNatToNat(res, interfaceID)
}

func (c *client) CreateNat(ctx context.Context, nat *api.Nat, ignoredErrors ...[]uint32) (*api.Nat, error) {
	res, err := c.DPDKironcoreClient.CreateNat(ctx, &dpdkproto.CreateNatRequest{
		InterfaceId: []byte(nat.NatMeta.InterfaceID),
		NatIp:       api.NetIPAddrToProtoIpAddress(nat.Spec.NatIP),
		MinPort:     nat.Spec.MinPort,
		MaxPort:     nat.Spec.MaxPort,
	})
	if err != nil {
		return &api.Nat{}, err
	}
	retNat := &api.Nat{
		TypeMeta: api.TypeMeta{Kind: api.NatKind},
		NatMeta:  nat.NatMeta,
		Status:   api.ProtoStatusToStatus(res.Status),
	}
	if res.GetStatus().GetCode() != 0 {
		return retNat, errors.GetError(res.Status, ignoredErrors)
	}

	underlayRoute, err := netip.ParseAddr(string(res.GetUnderlayRoute()))
	if err != nil {
		return retNat, fmt.Errorf("error parsing underlay route: %w", err)
	}

	retNat.Spec = nat.Spec
	retNat.Spec.UnderlayRoute = &underlayRoute
	return retNat, nil
}

func (c *client) DeleteNat(ctx context.Context, interfaceID string, ignoredErrors ...[]uint32) (*api.Nat, error) {
	res, err := c.DPDKironcoreClient.DeleteNat(ctx, &dpdkproto.DeleteNatRequest{
		InterfaceId: []byte(interfaceID),
	})
	if err != nil {
		return &api.Nat{}, err
	}
	retNat := &api.Nat{
		TypeMeta: api.TypeMeta{Kind: api.NatKind},
		NatMeta:  api.NatMeta{InterfaceID: interfaceID},
		Status:   api.ProtoStatusToStatus(res.Status),
	}
	if res.Status.GetCode() != 0 {
		return retNat, errors.GetError(res.Status, ignoredErrors)
	}
	return retNat, nil
}

func (c *client) ListLocalNats(ctx context.Context, natIP *netip.Addr, ignoredErrors ...[]uint32) (*api.NatList, error) {
	return c.ListNats(ctx, natIP, "local", ignoredErrors...)
}

func (c *client) CreateNeighborNat(ctx context.Context, nNat *api.NeighborNat, ignoredErrors ...[]uint32) (*api.NeighborNat, error) {
	if nNat.Spec.UnderlayRoute == nil {
		return nil, fmt.Errorf("underlayRoute needs to be specified")
	}
	res, err := c.DPDKironcoreClient.CreateNeighborNat(ctx, &dpdkproto.CreateNeighborNatRequest{
		NatIp:         api.NetIPAddrToProtoIpAddress(nNat.NatIP),
		Vni:           nNat.Spec.Vni,
		MinPort:       nNat.Spec.MinPort,
		MaxPort:       nNat.Spec.MaxPort,
		UnderlayRoute: []byte(nNat.Spec.UnderlayRoute.String()),
	})
	if err != nil {
		return &api.NeighborNat{}, err
	}
	retnNat := &api.NeighborNat{
		TypeMeta:        api.TypeMeta{Kind: api.NeighborNatKind},
		NeighborNatMeta: nNat.NeighborNatMeta,
		Status:          api.ProtoStatusToStatus(res.Status),
	}
	if res.GetStatus().GetCode() != 0 {
		return retnNat, errors.GetError(res.Status, ignoredErrors)
	}
	retnNat.Spec = nNat.Spec
	return retnNat, nil
}

func (c *client) ListNats(ctx context.Context, natIP *netip.Addr, natType string, ignoredErrors ...[]uint32) (*api.NatList, error) {
	var nType int32
	switch strings.ToLower(natType) {
	case "local", "1":
		nType = 1
	case "neigh", "2", "neighbor":
		nType = 2
	case "any", "0", "":
		nType = 0
	default:
		return nil, fmt.Errorf("nat type can be only: Any = 0/Local = 1/Neigh(bor) = 2")
	}

	req := api.NetIPAddrToProtoIpAddress(natIP)
	// nat type not defined, try both types
	var natEntries []*dpdkproto.NatEntry
	var status *dpdkproto.Status
	var err error
	switch nType {
	case 0:
		res1, err1 := c.DPDKironcoreClient.ListLocalNats(ctx, &dpdkproto.ListLocalNatsRequest{NatIp: req})
		if err1 != nil {
			return nil, err1
		}
		res2, err2 := c.DPDKironcoreClient.ListNeighborNats(ctx, &dpdkproto.ListNeighborNatsRequest{NatIp: req})
		if err2 != nil {
			return nil, err2
		}
		natEntries = append(natEntries, res1.NatEntries...)
		natEntries = append(natEntries, res2.NatEntries...)
	case 1:
		res, err := c.DPDKironcoreClient.ListLocalNats(ctx, &dpdkproto.ListLocalNatsRequest{NatIp: req})
		if err != nil {
			return nil, err
		}
		natEntries = res.GetNatEntries()
		status = res.Status
	case 2:
		res, err := c.DPDKironcoreClient.ListNeighborNats(ctx, &dpdkproto.ListNeighborNatsRequest{NatIp: req})
		if err != nil {
			return nil, err
		}
		natEntries = res.GetNatEntries()
		status = res.Status
	}

	var nats = make([]api.Nat, len(natEntries))
	var nat api.Nat
	for i, natEntry := range natEntries {

		var underlayRoute, vipIP netip.Addr
		if natEntry.GetUnderlayRoute() != nil {
			underlayRoute, err = netip.ParseAddr(string(natEntry.GetUnderlayRoute()))
			if err != nil {
				return nil, fmt.Errorf("error parsing underlay route: %w", err)
			}
			nat.Spec.UnderlayRoute = &underlayRoute
			nat.Spec.NatIP = nil
			nat.Kind = api.NeighborNatKind
		} else if natEntry.GetNatIp() != nil {
			vipIP, err = netip.ParseAddr(string(natEntry.GetNatIp().GetAddress()))
			if err != nil {
				return nil, fmt.Errorf("error parsing nat ip: %w", err)
			}
			nat.Spec.NatIP = &vipIP
			nat.Kind = api.NatKind
		}
		nat.Spec.MinPort = natEntry.MinPort
		nat.Spec.MaxPort = natEntry.MaxPort
		nat.Spec.Vni = natEntry.Vni
		nats[i] = nat
	}
	return &api.NatList{
		TypeMeta:    api.TypeMeta{Kind: api.NatListKind},
		NatListMeta: api.NatListMeta{NatIP: natIP, NatType: natType},
		Items:       nats,
		Status:      api.ProtoStatusToStatus(status),
	}, nil
}

func (c *client) DeleteNeighborNat(ctx context.Context, neigbhorNat *api.NeighborNat, ignoredErrors ...[]uint32) (*api.NeighborNat, error) {
	res, err := c.DPDKironcoreClient.DeleteNeighborNat(ctx, &dpdkproto.DeleteNeighborNatRequest{
		NatIp:   api.NetIPAddrToProtoIpAddress(neigbhorNat.NatIP),
		Vni:     neigbhorNat.Spec.Vni,
		MinPort: neigbhorNat.Spec.MinPort,
		MaxPort: neigbhorNat.Spec.MaxPort,
	})
	if err != nil {
		return &api.NeighborNat{}, err
	}
	nnat := &api.NeighborNat{
		TypeMeta:        api.TypeMeta{Kind: api.NeighborNatKind},
		NeighborNatMeta: neigbhorNat.NeighborNatMeta,
		Status:          api.ProtoStatusToStatus(res.Status),
	}
	if res.GetStatus().GetCode() != 0 {
		return nnat, errors.GetError(res.Status, ignoredErrors)
	}
	return nnat, nil
}

func (c *client) ListNeighborNats(ctx context.Context, natIP *netip.Addr, ignoredErrors ...[]uint32) (*api.NatList, error) {
	return c.ListNats(ctx, natIP, "neigh", ignoredErrors...)
}

func (c *client) ListFirewallRules(ctx context.Context, interfaceID string, ignoredErrors ...[]uint32) (*api.FirewallRuleList, error) {
	res, err := c.DPDKironcoreClient.ListFirewallRules(ctx, &dpdkproto.ListFirewallRulesRequest{
		InterfaceId: []byte(interfaceID),
	})
	if err != nil {
		return &api.FirewallRuleList{}, err
	}

	fwRules := make([]api.FirewallRule, len(res.GetRules()))
	for i, dpdkFwRule := range res.GetRules() {
		fwRule, err := api.ProtoFwRuleToFwRule(dpdkFwRule, interfaceID)
		if err != nil {
			return &api.FirewallRuleList{}, err
		}
		fwRules[i] = *fwRule
	}

	return &api.FirewallRuleList{
		TypeMeta:             api.TypeMeta{Kind: api.FirewallRuleListKind},
		FirewallRuleListMeta: api.FirewallRuleListMeta{InterfaceID: interfaceID},
		Items:                fwRules,
		Status:               api.ProtoStatusToStatus(res.Status),
	}, nil
}

func (c *client) CreateFirewallRule(ctx context.Context, fwRule *api.FirewallRule, ignoredErrors ...[]uint32) (*api.FirewallRule, error) {
	var action, direction uint8

	switch strings.ToLower(fwRule.Spec.FirewallAction) {
	case "accept", "allow", "1":
		action = 1
		fwRule.Spec.FirewallAction = "Accept"
	case "drop", "deny", "0":
		action = 0
		fwRule.Spec.FirewallAction = "Drop"
	default:
		return &api.FirewallRule{}, fmt.Errorf("firewall action can be only: drop/deny/0|accept/allow/1")
	}

	switch strings.ToLower(fwRule.Spec.TrafficDirection) {
	case "ingress", "0":
		direction = 0
		fwRule.Spec.TrafficDirection = "Ingress"
	case "egress", "1":
		direction = 1
		fwRule.Spec.TrafficDirection = "Egress"
	default:
		return &api.FirewallRule{}, fmt.Errorf("traffic direction can be only: Ingress = 0/Egress = 1")
	}

	if fwRule.Spec.SourcePrefix == nil {
		return nil, fmt.Errorf("source prefix needs to be specified")
	}
	fwRuleSrcPrefixAddr := fwRule.Spec.SourcePrefix.Addr()
	if fwRule.Spec.DestinationPrefix == nil {
		return nil, fmt.Errorf("destination prefix needs to be specified")
	}
	fwRuleDstPrefixAddr := fwRule.Spec.DestinationPrefix.Addr()
	req := dpdkproto.CreateFirewallRuleRequest{
		InterfaceId: []byte(fwRule.FirewallRuleMeta.InterfaceID),
		Rule: &dpdkproto.FirewallRule{
			Id:        []byte(fwRule.Spec.RuleID),
			Direction: dpdkproto.TrafficDirection(direction),
			Action:    dpdkproto.FirewallAction(action),
			Priority:  fwRule.Spec.Priority,
			SourcePrefix: &dpdkproto.Prefix{
				Ip:     api.NetIPAddrToProtoIpAddress(&fwRuleSrcPrefixAddr),
				Length: uint32(fwRule.Spec.SourcePrefix.Bits()),
			},
			DestinationPrefix: &dpdkproto.Prefix{
				Ip:     api.NetIPAddrToProtoIpAddress(&fwRuleDstPrefixAddr),
				Length: uint32(fwRule.Spec.DestinationPrefix.Bits()),
			},
			ProtocolFilter: fwRule.Spec.ProtocolFilter,
		},
	}

	res, err := c.DPDKironcoreClient.CreateFirewallRule(ctx, &req)
	if err != nil {
		return &api.FirewallRule{}, err
	}
	retFwrule := &api.FirewallRule{
		TypeMeta:         api.TypeMeta{Kind: api.FirewallRuleKind},
		FirewallRuleMeta: api.FirewallRuleMeta{InterfaceID: fwRule.InterfaceID},
		Spec:             api.FirewallRuleSpec{RuleID: fwRule.Spec.RuleID},
		Status:           api.ProtoStatusToStatus(res.Status)}
	if res.GetStatus().GetCode() != 0 {
		return retFwrule, errors.GetError(res.Status, ignoredErrors)
	}
	retFwrule.Spec = fwRule.Spec
	return retFwrule, nil
}

func (c *client) GetFirewallRule(ctx context.Context, interfaceID string, ruleID string, ignoredErrors ...[]uint32) (*api.FirewallRule, error) {
	res, err := c.DPDKironcoreClient.GetFirewallRule(ctx, &dpdkproto.GetFirewallRuleRequest{
		InterfaceId: []byte(interfaceID),
		RuleId:      []byte(ruleID),
	})
	if err != nil {
		return &api.FirewallRule{}, err
	}
	if res.GetStatus().GetCode() != 0 {
		return &api.FirewallRule{
			TypeMeta:         api.TypeMeta{Kind: api.FirewallRuleKind},
			FirewallRuleMeta: api.FirewallRuleMeta{InterfaceID: interfaceID},
			Spec:             api.FirewallRuleSpec{RuleID: ruleID},
			Status:           api.ProtoStatusToStatus(res.Status),
		}, errors.GetError(res.Status, ignoredErrors)
	}

	return api.ProtoFwRuleToFwRule(res.Rule, interfaceID)
}

func (c *client) DeleteFirewallRule(ctx context.Context, interfaceID string, ruleID string, ignoredErrors ...[]uint32) (*api.FirewallRule, error) {
	res, err := c.DPDKironcoreClient.DeleteFirewallRule(ctx, &dpdkproto.DeleteFirewallRuleRequest{
		InterfaceId: []byte(interfaceID),
		RuleId:      []byte(ruleID),
	})
	if err != nil {
		return &api.FirewallRule{}, err
	}
	retFwrule := &api.FirewallRule{
		TypeMeta:         api.TypeMeta{Kind: api.FirewallRuleKind},
		FirewallRuleMeta: api.FirewallRuleMeta{InterfaceID: interfaceID},
		Spec:             api.FirewallRuleSpec{RuleID: ruleID},
		Status:           api.ProtoStatusToStatus(res.Status),
	}
	if res.GetStatus().GetCode() != 0 {
		return retFwrule, errors.GetError(res.Status, ignoredErrors)
	}
	return retFwrule, nil
}

func (c *client) CheckInitialized(ctx context.Context, ignoredErrors ...[]uint32) (*api.Initialized, error) {
	res, err := c.DPDKironcoreClient.CheckInitialized(ctx, &dpdkproto.CheckInitializedRequest{})
	if err != nil {
		return &api.Initialized{}, err
	}
	retInitialized := &api.Initialized{
		TypeMeta: api.TypeMeta{Kind: api.InitializedKind},
		Status:   api.ProtoStatusToStatus(res.Status),
	}
	if res.GetStatus().GetCode() != 0 {
		return retInitialized, errors.GetError(res.Status, ignoredErrors)
	}
	retInitialized.Spec.UUID = res.Uuid
	return retInitialized, nil
}

func (c *client) Initialize(ctx context.Context, ignoredErrors ...[]uint32) (*api.Initialized, error) {
	res, err := c.DPDKironcoreClient.Initialize(ctx, &dpdkproto.InitializeRequest{})
	if err != nil {
		return &api.Initialized{}, err
	}
	retInit := &api.Initialized{
		TypeMeta: api.TypeMeta{Kind: api.InitializedKind},
		Status:   api.ProtoStatusToStatus(res.Status),
	}
	if res.GetStatus().GetCode() != 0 {
		return retInit, errors.GetError(res.Status, ignoredErrors)
	}
	retInit.Spec.UUID = res.Uuid
	return retInit, nil
}

func (c *client) GetVni(ctx context.Context, vni uint32, vniType uint8, ignoredErrors ...[]uint32) (*api.Vni, error) {
	res, err := c.DPDKironcoreClient.CheckVniInUse(ctx, &dpdkproto.CheckVniInUseRequest{
		Vni:  vni,
		Type: dpdkproto.VniType(vniType),
	})
	if err != nil {
		return &api.Vni{}, err
	}
	retVni := &api.Vni{
		TypeMeta: api.TypeMeta{Kind: api.VniKind},
		VniMeta:  api.VniMeta{VNI: vni, VniType: vniType},
		Status:   api.ProtoStatusToStatus(res.Status),
	}
	if res.GetStatus().GetCode() != 0 {
		return retVni, errors.GetError(res.Status, ignoredErrors)
	}
	retVni.Spec.InUse = res.InUse
	return retVni, nil
}

func (c *client) ResetVni(ctx context.Context, vni uint32, vniType uint8, ignoredErrors ...[]uint32) (*api.Vni, error) {
	res, err := c.DPDKironcoreClient.ResetVni(ctx, &dpdkproto.ResetVniRequest{
		Vni:  vni,
		Type: dpdkproto.VniType(vniType),
	})
	if err != nil {
		return &api.Vni{}, err
	}
	retVni := &api.Vni{
		TypeMeta: api.TypeMeta{Kind: api.VniKind},
		VniMeta:  api.VniMeta{VNI: vni, VniType: vniType},
		Status:   api.ProtoStatusToStatus(res.Status),
	}
	if res.GetStatus().GetCode() != 0 {
		return retVni, errors.GetError(res.Status, ignoredErrors)
	}
	return retVni, nil
}

func (c *client) GetVersion(ctx context.Context, version *api.Version, ignoredErrors ...[]uint32) (*api.Version, error) {
	version.ClientProtocol = strings.TrimSpace(dpdkproto.GeneratedFrom)
	res, err := c.DPDKironcoreClient.GetVersion(ctx, &dpdkproto.GetVersionRequest{
		ClientProtocol: version.ClientProtocol,
		ClientName:     version.ClientName,
		ClientVersion:  version.ClientVersion,
	})
	if err != nil {
		return &api.Version{}, err
	}
	version.Status = api.ProtoStatusToStatus(res.Status)
	if res.GetStatus().GetCode() != 0 {
		return version, errors.GetError(res.Status, ignoredErrors)
	}
	version.Spec.ServiceProtocol = res.ServiceProtocol
	version.Spec.ServiceVersion = res.ServiceVersion
	return version, nil
}

func (c *client) CaptureStart(ctx context.Context, capture *api.CaptureStart, ignoredErrors ...[]uint32) (*api.CaptureStart, error) {
	var interfaces = make([]*dpdkproto.CapturedInterface, 0, len(capture.Spec.Interfaces))

	for _, iface := range capture.Spec.Interfaces {
		protoInterface := &dpdkproto.CapturedInterface{}

		captureIfacetype, err := api.CaptureIfaceTypeToProtoIfaceType(iface.InterfaceType)
		if err != nil {
			fmt.Printf("error converting interface type for interface %s\n", iface.InterfaceInfo)
			continue
		}

		protoInterface.InterfaceType = captureIfacetype
		err = api.FillCaptureIfaceInfo(iface.InterfaceInfo, protoInterface)
		if err != nil {
			fmt.Printf("error filling interface info for interface %s\n", iface.InterfaceInfo)
			continue
		}

		interfaces = append(interfaces, protoInterface)
	}

	res, err := c.DPDKironcoreClient.CaptureStart(ctx, &dpdkproto.CaptureStartRequest{
		CaptureConfig: &dpdkproto.CaptureConfig{
			SinkNodeIp: api.NetIPAddrToProtoIpAddress(capture.CaptureStartMeta.Config.SinkNodeIP),
			UdpSrcPort: capture.CaptureStartMeta.Config.UdpSrcPort,
			UdpDstPort: capture.CaptureStartMeta.Config.UdpDstPort,
			Interfaces: interfaces,
		},
	})

	if err != nil {
		return &api.CaptureStart{}, err
	}
	capture.Status = api.ProtoStatusToStatus(res.Status)
	if res.GetStatus().GetCode() != 0 {
		return capture, errors.GetError(res.Status, ignoredErrors)
	}

	return capture, nil
}

func (c *client) CaptureStop(ctx context.Context, ignoredErrors ...[]uint32) (*api.CaptureStop, error) {
	res, err := c.DPDKironcoreClient.CaptureStop(ctx, &dpdkproto.CaptureStopRequest{})
	if err != nil {
		return &api.CaptureStop{}, err
	}
	if res.GetStatus().GetCode() != 0 {
		return &api.CaptureStop{}, errors.GetError(res.Status, ignoredErrors)
	}

	capture := &api.CaptureStop{
		Spec: api.CaptureStopSpec{
			InterfaceCount: res.StoppedInterfaceCnt,
		},
		Status: api.ProtoStatusToStatus(res.Status),
	}

	return capture, nil
}

func (c *client) CaptureStatus(ctx context.Context, ignoredErrors ...[]uint32) (*api.CaptureStatus, error) {
	res, err := c.DPDKironcoreClient.CaptureStatus(ctx, &dpdkproto.CaptureStatusRequest{})
	if err != nil {
		return &api.CaptureStatus{}, err
	}
	if res.GetStatus().GetCode() != 0 {
		return &api.CaptureStatus{}, errors.GetError(res.Status, ignoredErrors)
	}

	if !res.IsActive {
		capture := &api.CaptureStatus{
			Spec: api.CaptureGetStatusSpec{
				OperationStatus: false,
			},
			Status: api.ProtoStatusToStatus(res.Status),
		}
		return capture, nil
	}

	capture_interfaces := make([]api.CaptureInterface, len(res.CaptureConfig.Interfaces))
	for i, cap_iface := range res.CaptureConfig.Interfaces {
		capture_interfaces[i].InterfaceType, err = api.ProtoIfaceTypeToCaptureIfaceType(cap_iface.InterfaceType)
		if err != nil {
			return &api.CaptureStatus{}, err
		}
		capture_interfaces[i].InterfaceInfo, err = api.ProtoIfaceInfoToCaptureIfaceInfo(cap_iface)
		if err != nil {
			return &api.CaptureStatus{}, err
		}
	}

	sink_ip, err := api.ProtoIpAddressToNetIPAddr(res.CaptureConfig.SinkNodeIp)
	if err != nil {
		return &api.CaptureStatus{}, err
	}

	capture := &api.CaptureStatus{
		Spec: api.CaptureGetStatusSpec{
			OperationStatus: true,
			Config: api.CaptureConfig{
				SinkNodeIP: sink_ip,
				UdpSrcPort: res.CaptureConfig.UdpSrcPort,
				UdpDstPort: res.CaptureConfig.UdpDstPort,
			},
			Interfaces: capture_interfaces,
		},
		Status: api.ProtoStatusToStatus(res.Status),
	}

	return capture, nil
}
