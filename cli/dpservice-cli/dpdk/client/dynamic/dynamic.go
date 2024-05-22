// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package dynamic

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/ironcore-dev/dpservice-go/api"
	structured "github.com/ironcore-dev/dpservice-go/client"
)

type ObjectKey interface {
	fmt.Stringer
	Name() string
}

type InterfaceKey struct {
	ID string
}

func (k InterfaceKey) String() string {
	return k.ID
}

func (k InterfaceKey) Name() string {
	return k.ID
}

type PrefixKey struct {
	InterfaceID string
	Prefix      netip.Prefix
}

func (k PrefixKey) String() string {
	return fmt.Sprintf("%s/%s", k.InterfaceID, k.Prefix)
}

func (k PrefixKey) Name() string {
	return k.Prefix.String()
}

type VirtualIPKey struct {
	InterfaceID string
}

func (k VirtualIPKey) String() string {
	return k.InterfaceID
}

func (k VirtualIPKey) Name() string {
	return k.InterfaceID
}

type RouteKey struct {
	VNI        uint32
	Prefix     netip.Prefix
	NextHopVNI uint32
	NextHopIP  netip.Addr
}

func (k RouteKey) String() string {
	return fmt.Sprintf("%d:%s-%d:%s", k.VNI, k.Prefix, k.NextHopVNI, k.NextHopIP)
}

func (k RouteKey) Name() string {
	return fmt.Sprintf("%s-%d:%s", k.Prefix, k.NextHopVNI, k.NextHopIP)
}

type LoadBalancerKey struct {
	ID string
}

func (k LoadBalancerKey) String() string {
	return k.ID
}

func (k LoadBalancerKey) Name() string {
	return k.ID
}

type LoadBalancerPrefixKey struct {
	Prefix      netip.Prefix
	InterfaceID string
}

func (k LoadBalancerPrefixKey) String() string {
	return fmt.Sprintf("%s-%v", k.InterfaceID, k.Prefix)
}

func (k LoadBalancerPrefixKey) Name() string {
	return k.String()
}

type LoadBalancerTargetKey struct {
	TargetIP       netip.Addr
	LoadBalancerID string
}

func (k LoadBalancerTargetKey) String() string {
	return fmt.Sprintf("%s-%v", k.LoadBalancerID, k.TargetIP)
}

func (k LoadBalancerTargetKey) Name() string {
	return k.String()
}

type NatKey struct {
	InterfaceID string
}

func (k NatKey) String() string {
	return k.InterfaceID
}

func (k NatKey) Name() string {
	return k.String()
}

type NeighborNatKey struct {
	NatIP   netip.Addr
	Vni     uint32
	MinPort uint32
	MaxPort uint32
}

func (k NeighborNatKey) String() string {
	return fmt.Sprintf("%d-%v:<%d,%d>", k.Vni, k.NatIP, k.MinPort, k.MaxPort)
}

func (k NeighborNatKey) Name() string {
	return fmt.Sprintf("%d-%v", k.Vni, k.NatIP)
}

type FirewallRuleKey struct {
	RuleID      string
	InterfaceID string
}

func (k FirewallRuleKey) String() string {
	return fmt.Sprintf("%s-%s", k.InterfaceID, k.RuleID)
}

func (k FirewallRuleKey) Name() string {
	return k.String()
}

type emptyKey struct{}

func (emptyKey) String() string {
	return ""
}

func (emptyKey) Name() string {
	return ""
}

var EmptyKey ObjectKey = emptyKey{}

// returns object key (parameters needed for deletion)
func ObjectKeyFromObject(obj any) ObjectKey {
	switch obj := obj.(type) {
	case *api.Interface:
		return InterfaceKey{ID: obj.ID}
	case *api.Prefix:
		return PrefixKey{
			InterfaceID: obj.InterfaceID,
			Prefix:      obj.Spec.Prefix,
		}
	case *api.Route:
		return RouteKey{
			VNI:    obj.VNI,
			Prefix: *obj.Spec.Prefix,
		}
	case *api.VirtualIP:
		return VirtualIPKey{
			InterfaceID: obj.InterfaceID,
		}
	case *api.LoadBalancer:
		return LoadBalancerKey{
			ID: obj.ID,
		}
	case *api.LoadBalancerPrefix:
		return LoadBalancerPrefixKey{
			Prefix:      obj.Spec.Prefix,
			InterfaceID: obj.InterfaceID,
		}
	case *api.LoadBalancerTarget:
		return LoadBalancerTargetKey{
			TargetIP:       *obj.Spec.TargetIP,
			LoadBalancerID: obj.LoadbalancerID,
		}
	case *api.Nat:
		return NatKey{
			InterfaceID: obj.InterfaceID,
		}
	case *api.NeighborNat:
		return NeighborNatKey{
			NatIP:   *obj.NatIP,
			Vni:     obj.Spec.Vni,
			MinPort: obj.Spec.MinPort,
			MaxPort: obj.Spec.MaxPort,
		}
	case *api.FirewallRule:
		return FirewallRuleKey{
			RuleID:      obj.Spec.RuleID,
			InterfaceID: obj.InterfaceID,
		}
	default:
		return EmptyKey
	}
}

type Client interface {
	Create(ctx context.Context, obj any) (any, error)
	Delete(ctx context.Context, obj any) (any, error)
}

type client struct {
	structured structured.Client
}

func (c *client) Create(ctx context.Context, obj any) (any, error) {
	switch obj := obj.(type) {
	case *api.Interface:
		res, err := c.structured.CreateInterface(ctx, obj)
		if err != nil {
			return res, err
		}
		*obj = *res
		return obj, nil
	case *api.Prefix:
		res, err := c.structured.CreatePrefix(ctx, obj)
		if err != nil {
			return res, err
		}
		*obj = *res
		return obj, nil
	case *api.Route:
		res, err := c.structured.CreateRoute(ctx, obj)
		if err != nil {
			return res, err
		}
		*obj = *res
		return obj, nil
	case *api.VirtualIP:
		res, err := c.structured.CreateVirtualIP(ctx, obj)
		if err != nil {
			return res, err
		}
		*obj = *res
		return obj, nil
	case *api.LoadBalancer:
		res, err := c.structured.CreateLoadBalancer(ctx, obj)
		if err != nil {
			return res, err
		}
		*obj = *res
		return obj, nil
	case *api.LoadBalancerPrefix:
		res, err := c.structured.CreateLoadBalancerPrefix(ctx, obj)
		if err != nil {
			return res, err
		}
		*obj = *res
		return obj, nil
	case *api.LoadBalancerTarget:
		res, err := c.structured.CreateLoadBalancerTarget(ctx, obj)
		if err != nil {
			return res, err
		}
		*obj = *res
		return obj, nil
	case *api.Nat:
		res, err := c.structured.CreateNat(ctx, obj)
		if err != nil {
			return res, err
		}
		*obj = *res
		return obj, nil
	case *api.NeighborNat:
		res, err := c.structured.CreateNeighborNat(ctx, obj)
		if err != nil {
			return res, err
		}
		*obj = *res
		return obj, nil
	case *api.FirewallRule:
		res, err := c.structured.CreateFirewallRule(ctx, obj)
		if err != nil {
			return res, err
		}
		*obj = *res
		return obj, nil
	default:
		return obj, fmt.Errorf("unsupported object %T", obj)
	}
}

func (c *client) Delete(ctx context.Context, obj any) (any, error) {
	switch obj := obj.(type) {
	case *api.Interface:
		return c.structured.DeleteInterface(ctx, obj.ID)
	case *api.Prefix:
		return c.structured.DeletePrefix(ctx, obj.InterfaceID, &obj.Spec.Prefix)
	case *api.Route:
		return c.structured.DeleteRoute(ctx, obj.VNI, obj.Spec.Prefix)
	case *api.VirtualIP:
		return c.structured.DeleteVirtualIP(ctx, obj.InterfaceID)
	case *api.LoadBalancer:
		return c.structured.DeleteLoadBalancer(ctx, obj.ID)
	case *api.LoadBalancerPrefix:
		return c.structured.DeleteLoadBalancerPrefix(ctx, obj.InterfaceID, &obj.Spec.Prefix)
	case *api.LoadBalancerTarget:
		return c.structured.DeleteLoadBalancerTarget(ctx, obj.LoadbalancerID, obj.Spec.TargetIP)
	case *api.Nat:
		return c.structured.DeleteNat(ctx, obj.InterfaceID)
	case *api.NeighborNat:
		return c.structured.DeleteNeighborNat(ctx, obj)
	case *api.FirewallRule:
		return c.structured.DeleteFirewallRule(ctx, obj.InterfaceID, obj.Spec.RuleID)
	default:
		return obj, fmt.Errorf("unsupported object %T", obj)
	}
}

func NewFromStructured(structured structured.Client) Client {
	return &client{structured: structured}
}
