// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package runtime

import "github.com/ironcore-dev/dpservice-go/api"

var DefaultScheme = NewScheme()

func init() {
	if err := DefaultScheme.Add(
		&api.Interface{},
		&api.InterfaceList{},
		&api.Prefix{},
		&api.PrefixList{},
		&api.Route{},
		&api.RouteList{},
		&api.VirtualIP{},
		&api.LoadBalancer{},
		&api.LoadBalancerTarget{},
		&api.LoadBalancerPrefix{},
		&api.LoadBalancerTargetList{},
		&api.Nat{},
		&api.NatList{},
		&api.NeighborNat{},
		&api.FirewallRule{},
		&api.Vni{},
	); err != nil {
		panic(err)
	}
}
