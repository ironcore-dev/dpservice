// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"net/netip"

	"github.com/ironcore-dev/dpservice-go/api"
	"github.com/ironcore-dev/dpservice-go/errors"
	dpdkproto "github.com/ironcore-dev/dpservice-go/proto"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const positiveTestIfaceID = "vm5"
const positiveTestVNI = uint32(500)
const negativeTestIfaceID = "vm4"
const negativeTestVNI = uint32(400)

var _ = Describe("interface", Label("interface"), func() {
	ctx := context.TODO()

	Context("When using interface functions", Ordered, func() {
		var iface api.Interface
		var res *api.Interface
		var err error

		It("should create successfully", func() {
			ipv4 := netip.MustParseAddr("10.200.1.5")
			ipv6 := netip.MustParseAddr("2000:200:1::5")
			iface = api.Interface{
				InterfaceMeta: api.InterfaceMeta{
					ID: positiveTestIfaceID,
				},
				Spec: api.InterfaceSpec{
					IPv4:   &ipv4,
					IPv6:   &ipv6,
					VNI:    positiveTestVNI,
					Device: "net_tap5",
					Metering: &api.MeteringParams{
						TotalRate:  100,
						PublicRate: 50,
					},
				},
			}

			vni, err := dpdkClient.GetVni(ctx, positiveTestVNI, 0)
			Expect(err).ToNot(HaveOccurred())

			Expect(vni.Spec.InUse).To(BeFalse())

			res, err = dpdkClient.CreateInterface(ctx, &iface)
			Expect(err).ToNot(HaveOccurred())

			Expect(res.ID).To(Equal("vm5"))
			Expect(res.Spec.VNI).To(Equal(positiveTestVNI))

			vni, err = dpdkClient.GetVni(ctx, positiveTestVNI, 0)
			Expect(err).ToNot(HaveOccurred())

			Expect(vni.Spec.InUse).To(BeTrue())

			vni, err = dpdkClient.ResetVni(ctx, positiveTestVNI, 2)
			Expect(err).ToNot(HaveOccurred())

			Expect(vni.Spec.InUse).To(BeFalse())
		})

		It("should not be created when already existing", func() {
			res, err := dpdkClient.CreateInterface(ctx, &iface)
			Expect(err).To(HaveOccurred())

			Expect(res.Status.Code).To(Equal(uint32(errors.ALREADY_EXISTS)))
		})

		It("should get successfully", func() {
			res, err = dpdkClient.GetInterface(ctx, iface.ID)
			Expect(err).ToNot(HaveOccurred())

			Expect(res.Spec.IPv4.String()).To(Equal("10.200.1.5"))
			Expect(res.Spec.IPv6.String()).To(Equal("2000:200:1::5"))
			Expect(res.Spec.Metering.TotalRate).To(Equal(uint64(0))) //MeteringRarams shouldn't take any effect on tap devices
			Expect(res.Spec.Metering.PublicRate).To(Equal(uint64(0)))
		})

		It("should list successfully", func() {
			ifaces, err := dpdkClient.ListInterfaces(ctx)
			Expect(err).ToNot(HaveOccurred())

			Expect(len(ifaces.Items)).To(Equal(1))
			Expect(ifaces.Items[0].Kind).To(Equal("Interface"))
		})

		It("should delete successfully", func() {
			By("deleting the interface")
			res, err = dpdkClient.DeleteInterface(ctx, iface.ID)
			Expect(err).ToNot(HaveOccurred())

			By("trying to get the deleted interface")
			res, err = dpdkClient.GetInterface(ctx, iface.ID)
			Expect(err).To(HaveOccurred())
			Expect(res.Status.Code).To(Equal(uint32(errors.NOT_FOUND)))

			By("trying to delete the interface again")
			res, err = dpdkClient.DeleteInterface(ctx, iface.ID)
			Expect(err).To(HaveOccurred())
			Expect(res.Status.Code).To(Equal(uint32(errors.NOT_FOUND)))
		})
	})
})

var _ = Describe("interface related", func() {
	ctx := context.TODO()

	// Creates the network interface object
	// OncePerOrdered decorator will run this only once per Ordered spec and not before every It spec
	BeforeEach(OncePerOrdered, func() {
		ipv4 := netip.MustParseAddr("10.200.1.5")
		ipv6 := netip.MustParseAddr("2000:200:1::5")
		iface := api.Interface{
			InterfaceMeta: api.InterfaceMeta{
				ID: positiveTestIfaceID,
			},
			Spec: api.InterfaceSpec{
				IPv4:   &ipv4,
				IPv6:   &ipv6,
				VNI:    positiveTestVNI,
				Device: "net_tap5",
			},
		}
		_, err := dpdkClient.CreateInterface(ctx, &iface)
		Expect(err).ToNot(HaveOccurred())

		// Deletes the network interface object after spec is completed
		DeferCleanup(func(ctx SpecContext) {
			_, err := dpdkClient.DeleteInterface(ctx, positiveTestIfaceID)
			Expect(err).ToNot(HaveOccurred())
		})
	})

	Context("When using prefix functions", Label("prefix"), Ordered, func() {
		var prefix api.Prefix
		var res *api.Prefix
		var err error

		It("should create successfully", func() {
			prefix = api.Prefix{
				PrefixMeta: api.PrefixMeta{
					InterfaceID: positiveTestIfaceID,
				},
				Spec: api.PrefixSpec{
					Prefix: netip.MustParsePrefix("10.20.30.0/24"),
				},
			}

			res, err = dpdkClient.CreatePrefix(ctx, &prefix)
			Expect(err).ToNot(HaveOccurred())

			Expect(res.InterfaceID).To(Equal(positiveTestIfaceID))
			Expect(res.Spec.Prefix.String()).To(Equal("10.20.30.0/24"))
		})

		It("should not be created when already existing", func() {
			res, err := dpdkClient.CreatePrefix(ctx, &prefix)
			Expect(err).To(HaveOccurred())

			Expect(res.Status.Code).To(Equal(uint32(errors.ROUTE_EXISTS)))
		})

		It("should list successfully", func() {
			prefixes, err := dpdkClient.ListPrefixes(ctx, positiveTestIfaceID)
			Expect(err).ToNot(HaveOccurred())

			Expect(len(prefixes.Items)).To(Equal(1))
			Expect(prefixes.Items[0].Kind).To(Equal("Prefix"))
		})

		It("should delete successfully", func() {
			res, err = dpdkClient.DeletePrefix(ctx, prefix.InterfaceID, &prefix.Spec.Prefix)
			Expect(err).ToNot(HaveOccurred())

			prefixes, err := dpdkClient.ListPrefixes(ctx, positiveTestIfaceID)
			Expect(err).ToNot(HaveOccurred())
			Expect(len(prefixes.Items)).To(Equal(0))

			res, err = dpdkClient.DeletePrefix(ctx, prefix.InterfaceID, &prefix.Spec.Prefix)
			Expect(err).To(HaveOccurred())
			Expect(res.Status.Code).To(Equal(uint32(errors.ROUTE_NOT_FOUND)))
		})
	})

	Context("When using lbprefix functions", Label("lbprefix"), Ordered, func() {
		var lbprefix api.LoadBalancerPrefix
		var res *api.LoadBalancerPrefix
		var err error

		It("should create successfully", func() {
			lbprefix = api.LoadBalancerPrefix{
				LoadBalancerPrefixMeta: api.LoadBalancerPrefixMeta{
					InterfaceID: positiveTestIfaceID,
				},
				Spec: api.LoadBalancerPrefixSpec{
					Prefix: netip.MustParsePrefix("10.10.10.0/24"),
				},
			}

			res, err = dpdkClient.CreateLoadBalancerPrefix(ctx, &lbprefix)
			Expect(err).ToNot(HaveOccurred())

			Expect(res.InterfaceID).To(Equal(positiveTestIfaceID))
			Expect(res.Spec.Prefix.String()).To(Equal("10.10.10.0/24"))
		})

		It("should not be created when already existing", func() {
			res, err := dpdkClient.CreateLoadBalancerPrefix(ctx, &lbprefix)
			Expect(err).To(HaveOccurred())

			Expect(res.Status.Code).To(Equal(uint32(errors.ALREADY_EXISTS)))
		})

		It("should list successfully", func() {
			lbprefixes, err := dpdkClient.ListLoadBalancerPrefixes(ctx, positiveTestIfaceID)
			Expect(err).ToNot(HaveOccurred())

			Expect(len(lbprefixes.Items)).To(Equal(1))
			Expect(lbprefixes.Items[0].Kind).To(Equal("LoadBalancerPrefix"))
		})

		It("should delete successfully", func() {
			res, err = dpdkClient.DeleteLoadBalancerPrefix(ctx, lbprefix.InterfaceID, &lbprefix.Spec.Prefix)
			Expect(err).ToNot(HaveOccurred())

			lbprefixes, err := dpdkClient.ListLoadBalancerPrefixes(ctx, positiveTestIfaceID)
			Expect(err).ToNot(HaveOccurred())
			Expect(len(lbprefixes.Items)).To(Equal(0))

			res, err = dpdkClient.DeleteLoadBalancerPrefix(ctx, lbprefix.InterfaceID, &lbprefix.Spec.Prefix)
			Expect(err).To(HaveOccurred())
			Expect(res.Status.Code).To(Equal(uint32(errors.NOT_FOUND)))
		})
	})

	Context("When using virtualIP functions", Label("vip"), Ordered, func() {
		var vip api.VirtualIP
		var res *api.VirtualIP
		var err error

		It("should create successfully", func() {
			ip := netip.MustParseAddr("20.20.20.20")
			vip = api.VirtualIP{
				VirtualIPMeta: api.VirtualIPMeta{
					InterfaceID: positiveTestIfaceID,
				},
				Spec: api.VirtualIPSpec{
					IP: &ip,
				},
			}

			res, err = dpdkClient.CreateVirtualIP(ctx, &vip)
			Expect(err).ToNot(HaveOccurred())

			Expect(res.InterfaceID).To(Equal(positiveTestIfaceID))
			Expect(res.Spec.IP.String()).To(Equal("20.20.20.20"))
		})

		It("should not be created when already existing", func() {
			res, err := dpdkClient.CreateVirtualIP(ctx, &vip)
			Expect(err).To(HaveOccurred())

			Expect(res.Status.Code).To(Equal(uint32(errors.SNAT_EXISTS)))
		})

		It("should get successfully", func() {
			res, err = dpdkClient.GetVirtualIP(ctx, positiveTestIfaceID)
			Expect(err).ToNot(HaveOccurred())

			Expect(res.InterfaceID).To(Equal(positiveTestIfaceID))
			Expect(res.Spec.UnderlayRoute).ToNot(BeNil())
		})

		It("should delete successfully", func() {
			res, err = dpdkClient.DeleteVirtualIP(ctx, vip.InterfaceID)
			Expect(err).ToNot(HaveOccurred())

			res, err = dpdkClient.GetVirtualIP(ctx, positiveTestIfaceID)
			Expect(err).To(HaveOccurred())

			res, err = dpdkClient.DeleteVirtualIP(ctx, vip.InterfaceID)
			Expect(err).To(HaveOccurred())
			Expect(res.Status.Code).To(Equal(uint32(errors.SNAT_NO_DATA)))
		})
	})

	Context("When using nat functions", Label("nat"), Ordered, func() {
		var nat api.Nat
		var res *api.Nat
		var err error

		It("should create successfully", func() {
			ip := netip.MustParseAddr("10.20.30.40")
			nat = api.Nat{
				NatMeta: api.NatMeta{
					InterfaceID: positiveTestIfaceID,
				},
				Spec: api.NatSpec{
					NatIP:   &ip,
					MinPort: 30000,
					MaxPort: 30100,
				},
			}

			res, err = dpdkClient.CreateNat(ctx, &nat)
			Expect(err).ToNot(HaveOccurred())

			Expect(res.InterfaceID).To(Equal(positiveTestIfaceID))
			Expect(res.Spec.NatIP.String()).To(Equal("10.20.30.40"))
		})

		It("should not be created when already existing", func() {
			res, err := dpdkClient.CreateNat(ctx, &nat)
			Expect(err).To(HaveOccurred())

			Expect(res.Status.Code).To(Equal(uint32(errors.SNAT_EXISTS)))
		})

		It("should get successfully", func() {
			res, err = dpdkClient.GetNat(ctx, positiveTestIfaceID)
			Expect(err).ToNot(HaveOccurred())

			Expect(res.InterfaceID).To(Equal(positiveTestIfaceID))
			Expect(res.Spec.UnderlayRoute).ToNot(BeNil())
			Expect(res.Spec.MinPort).To(Equal(uint32(30000)))
		})

		It("should list localNats successfully", func() {
			localNats, err := dpdkClient.ListLocalNats(ctx, nat.Spec.NatIP)
			Expect(err).ToNot(HaveOccurred())

			Expect(len(localNats.Items)).To(Equal(1))
			Expect(localNats.Items[0].Kind).To(Equal(api.NatKind))
			Expect(localNats.Items[0].Spec.MinPort).To(Equal(uint32(30000)))
		})

		It("should delete successfully", func() {
			res, err = dpdkClient.DeleteNat(ctx, nat.InterfaceID)
			Expect(err).ToNot(HaveOccurred())

			res, err = dpdkClient.GetNat(ctx, positiveTestIfaceID)
			Expect(err).To(HaveOccurred())

			res, err = dpdkClient.DeleteNat(ctx, nat.InterfaceID)
			Expect(err).To(HaveOccurred())
			Expect(res.Status.Code).To(Equal(uint32(errors.SNAT_NO_DATA)))
		})
	})

	Context("When using neighbor nat functions", Label("neighbornat"), Ordered, func() {
		var neighborNat api.NeighborNat
		var res *api.NeighborNat
		var err error

		It("should create successfully", func() {
			natIp := netip.MustParseAddr("10.20.30.40")
			underlayRoute := netip.MustParseAddr("ff80::1")
			neighborNat = api.NeighborNat{
				NeighborNatMeta: api.NeighborNatMeta{
					NatIP: &natIp,
				},
				Spec: api.NeighborNatSpec{
					Vni:           100,
					MinPort:       30000,
					MaxPort:       30100,
					UnderlayRoute: &underlayRoute,
				},
			}

			res, err = dpdkClient.CreateNeighborNat(ctx, &neighborNat)
			Expect(err).ToNot(HaveOccurred())

			Expect(res.NatIP.String()).To(Equal("10.20.30.40"))
			Expect(res.Spec.Vni).To(Equal(uint32(100)))
		})

		It("should not be created when already existing", func() {
			res, err := dpdkClient.CreateNeighborNat(ctx, &neighborNat)
			Expect(err).To(HaveOccurred())

			Expect(res.Status.Code).To(Equal(uint32(errors.ALREADY_EXISTS)))
		})

		It("should list successfully", func() {
			neighborNats, err := dpdkClient.ListNeighborNats(ctx, neighborNat.NatIP)
			Expect(err).ToNot(HaveOccurred())

			Expect(len(neighborNats.Items)).To(Equal(1))
			Expect(neighborNats.Items[0].Kind).To(Equal(api.NeighborNatKind))
			Expect(neighborNats.Items[0].Spec.MinPort).To(Equal(uint32(30000)))
		})

		It("should list Nats successfully", func() {
			nats, err := dpdkClient.ListNats(ctx, neighborNat.NatIP, "any")
			Expect(err).ToNot(HaveOccurred())

			Expect(len(nats.Items)).To(Equal(1))
			Expect(nats.Items[0].Spec.MinPort).To(Equal(uint32(30000)))
		})

		It("should delete successfully", func() {
			res, err = dpdkClient.DeleteNeighborNat(ctx, &neighborNat)
			Expect(err).ToNot(HaveOccurred())

			neighborNats, err := dpdkClient.ListNeighborNats(ctx, neighborNat.NatIP)
			Expect(err).ToNot(HaveOccurred())
			Expect(len(neighborNats.Items)).To(Equal(0))

			res, err = dpdkClient.DeleteNeighborNat(ctx, &neighborNat)
			Expect(err).To(HaveOccurred())
			Expect(res.Status.Code).To(Equal(uint32(errors.NOT_FOUND)))
		})
	})

	Context("When using route functions", Label("route"), Ordered, func() {
		var route api.Route
		var res *api.Route
		var err error

		It("should create successfully", func() {
			prefix := netip.MustParsePrefix("10.100.3.0/24")
			nextHopIp := netip.MustParseAddr("fc00:2::64:0:1")
			route = api.Route{
				RouteMeta: api.RouteMeta{
					VNI: positiveTestVNI,
				},
				Spec: api.RouteSpec{
					Prefix: &prefix,
					NextHop: &api.RouteNextHop{
						VNI: 0,
						IP:  &nextHopIp,
					},
				},
			}
			res, err = dpdkClient.CreateRoute(ctx, &route)
			Expect(err).ToNot(HaveOccurred())

			Expect(res.VNI).To(Equal(positiveTestVNI))
			Expect(res.Spec.Prefix.String()).To(Equal("10.100.3.0/24"))
		})

		It("should not be created when already existing", func() {
			res, err := dpdkClient.CreateRoute(ctx, &route)
			Expect(err).To(HaveOccurred())

			Expect(res.Status.Code).To(Equal(uint32(errors.ROUTE_EXISTS)))
		})

		It("should list successfully", func() {
			routes, err := dpdkClient.ListRoutes(ctx, positiveTestVNI)
			Expect(err).ToNot(HaveOccurred())

			Expect(len(routes.Items)).To(Equal(1))
			Expect(routes.Items[0].Kind).To(Equal(api.RouteKind))
		})

		It("should delete successfully", func() {
			res, err = dpdkClient.DeleteRoute(ctx, route.VNI, route.Spec.Prefix)
			Expect(err).ToNot(HaveOccurred())

			routes, err := dpdkClient.ListRoutes(ctx, positiveTestVNI)
			Expect(err).ToNot(HaveOccurred())
			Expect(len(routes.Items)).To(Equal(0))

			res, err = dpdkClient.DeleteRoute(ctx, route.VNI, route.Spec.Prefix)
			Expect(err).To(HaveOccurred())
			Expect(res.Status.Code).To(Equal(uint32(errors.ROUTE_NOT_FOUND)))
		})
	})

	Context("When using firewall rule functions", Label("fwrule"), Ordered, func() {
		var fwRule api.FirewallRule
		var res *api.FirewallRule
		var err error

		It("should create successfully", func() {
			src := netip.MustParsePrefix("1.1.1.1/32")
			dst := netip.MustParsePrefix("5.5.5.0/24")
			fwRule = api.FirewallRule{
				FirewallRuleMeta: api.FirewallRuleMeta{
					InterfaceID: positiveTestIfaceID,
				},
				Spec: api.FirewallRuleSpec{
					RuleID:            "Rule1",
					TrafficDirection:  "ingress",
					FirewallAction:    "accept",
					Priority:          1000,
					SourcePrefix:      &src,
					DestinationPrefix: &dst,
					ProtocolFilter: &dpdkproto.ProtocolFilter{
						Filter: &dpdkproto.ProtocolFilter_Tcp{
							Tcp: &dpdkproto.TcpFilter{
								SrcPortLower: 1,
								SrcPortUpper: 65535,
								DstPortLower: 500,
								DstPortUpper: 600,
							},
						},
					},
				},
			}

			res, err = dpdkClient.CreateFirewallRule(ctx, &fwRule)
			Expect(err).ToNot(HaveOccurred())

			Expect(res.InterfaceID).To(Equal(positiveTestIfaceID))
			Expect(res.Spec.RuleID).To(Equal("Rule1"))
		})

		It("should not be created when already existing", func() {
			res, err := dpdkClient.CreateFirewallRule(ctx, &fwRule)
			Expect(err).To(HaveOccurred())

			Expect(res.Status.Code).To(Equal(uint32(errors.ALREADY_EXISTS)))
		})

		It("should get successfully", func() {
			res, err = dpdkClient.GetFirewallRule(ctx, fwRule.InterfaceID, fwRule.Spec.RuleID)
			Expect(err).ToNot(HaveOccurred())

			Expect(res.Spec.TrafficDirection).To(Equal("Ingress"))
			Expect(res.Spec.SourcePrefix.String()).To(Equal("1.1.1.1/32"))
		})

		It("should list successfully", func() {
			fwRules, err := dpdkClient.ListFirewallRules(ctx, fwRule.InterfaceID)
			Expect(err).ToNot(HaveOccurred())

			Expect(len(fwRules.Items)).To(Equal(1))
			Expect(fwRules.Items[0].Kind).To(Equal(api.FirewallRuleKind))
			Expect(fwRules.Items[0].Spec.Priority).To(Equal(uint32(1000)))
		})

		It("should delete successfully", func() {
			res, err = dpdkClient.DeleteFirewallRule(ctx, fwRule.InterfaceID, fwRule.Spec.RuleID)
			Expect(err).ToNot(HaveOccurred())

			res, err = dpdkClient.GetFirewallRule(ctx, fwRule.InterfaceID, fwRule.Spec.RuleID)
			Expect(err).To(HaveOccurred())
			Expect(res.Status.Code).To(Equal(uint32(errors.NOT_FOUND)))

			res, err = dpdkClient.DeleteFirewallRule(ctx, fwRule.InterfaceID, fwRule.Spec.RuleID)
			Expect(err).To(HaveOccurred())
			Expect(res.Status.Code).To(Equal(uint32(errors.NOT_FOUND)))
		})
	})
})

var _ = Describe("loadbalancer related", func() {
	ctx := context.TODO()

	Context("When using loadbalancer functions", Label("loadbalancer"), Ordered, func() {
		var lb api.LoadBalancer
		var res *api.LoadBalancer
		var err error

		It("should create successfully", func() {
			var lbVipIp = netip.MustParseAddr("10.20.30.40")
			lb = api.LoadBalancer{
				LoadBalancerMeta: api.LoadBalancerMeta{
					ID: "lb1",
				},
				Spec: api.LoadBalancerSpec{
					VNI:     100,
					LbVipIP: &lbVipIp,
					Lbports: []api.LBPort{
						{
							Protocol: 6,
							Port:     443,
						},
						{
							Protocol: 17,
							Port:     53,
						},
					},
				},
			}

			res, err = dpdkClient.CreateLoadBalancer(ctx, &lb)
			Expect(err).ToNot(HaveOccurred())

			Expect(res.ID).To(Equal("lb1"))
			Expect(res.Spec.VNI).To(Equal(uint32(100)))
		})

		It("should not be created when already existing", func() {
			res, err := dpdkClient.CreateLoadBalancer(ctx, &lb)
			Expect(err).To(HaveOccurred())

			Expect(res.Status.Code).To(Equal(uint32(errors.ALREADY_EXISTS)))
		})

		It("should get successfully", func() {
			res, err = dpdkClient.GetLoadBalancer(ctx, lb.ID)
			Expect(err).ToNot(HaveOccurred())

			Expect(res.Spec.LbVipIP.String()).To(Equal("10.20.30.40"))
			Expect(res.Spec.Lbports[0].Port).To(Equal(uint32(443)))
		})

		It("should delete successfully", func() {
			res, err = dpdkClient.DeleteLoadBalancer(ctx, lb.ID)
			Expect(err).ToNot(HaveOccurred())

			res, err = dpdkClient.GetLoadBalancer(ctx, lb.ID)
			Expect(err).To(HaveOccurred())
			Expect(res.Status.Code).To(Equal(uint32(errors.NOT_FOUND)))

			res, err = dpdkClient.DeleteLoadBalancer(ctx, lb.ID)
			Expect(err).To(HaveOccurred())
			Expect(res.Status.Code).To(Equal(uint32(errors.NOT_FOUND)))
		})
	})

	Context("When using loadbalancer target functions", Label("lbtarget"), Ordered, func() {
		var lbtarget api.LoadBalancerTarget
		var res *api.LoadBalancerTarget
		var lb api.LoadBalancer
		var err error

		It("should create successfully", func() {
			var lbVipIp = netip.MustParseAddr("10.20.30.40")
			lb = api.LoadBalancer{
				LoadBalancerMeta: api.LoadBalancerMeta{
					ID: "lb2",
				},
				Spec: api.LoadBalancerSpec{
					VNI:     positiveTestVNI,
					LbVipIP: &lbVipIp,
					Lbports: []api.LBPort{
						{
							Protocol: 6,
							Port:     443,
						},
						{
							Protocol: 17,
							Port:     53,
						},
					},
				},
			}

			_, err = dpdkClient.CreateLoadBalancer(ctx, &lb)
			Expect(err).ToNot(HaveOccurred())

			targetIp := netip.MustParseAddr("ff80::5")
			lbtarget = api.LoadBalancerTarget{
				LoadBalancerTargetMeta: api.LoadBalancerTargetMeta{
					LoadbalancerID: "lb2",
				},
				Spec: api.LoadBalancerTargetSpec{
					TargetIP: &targetIp,
				},
			}

			res, err = dpdkClient.CreateLoadBalancerTarget(ctx, &lbtarget)
			Expect(err).ToNot(HaveOccurred())

			Expect(res.LoadbalancerID).To(Equal("lb2"))
			Expect(res.Spec.TargetIP.String()).To(Equal("ff80::5"))
		})

		It("should not be created when already existing", func() {
			res, err := dpdkClient.CreateLoadBalancerTarget(ctx, &lbtarget)
			Expect(err).To(HaveOccurred())

			Expect(res.Status.Code).To(Equal(uint32(errors.ALREADY_EXISTS)))
		})

		It("should list successfully", func() {
			lbtargets, err := dpdkClient.ListLoadBalancerTargets(ctx, lbtarget.LoadbalancerID)
			Expect(err).ToNot(HaveOccurred())

			Expect(lbtargets.Items[0].LoadbalancerID).To(Equal("lb2"))
			Expect(len(lbtargets.Items)).To(Equal(1))
			Expect(lbtargets.Items[0].Kind).To(Equal(api.LoadBalancerTargetKind))
		})

		It("should delete successfully", func() {
			res, err = dpdkClient.DeleteLoadBalancerTarget(ctx, lbtarget.LoadbalancerID, lbtarget.Spec.TargetIP)
			Expect(err).ToNot(HaveOccurred())

			lbtargets, err := dpdkClient.ListLoadBalancerTargets(ctx, lbtarget.LoadbalancerID)
			Expect(err).ToNot(HaveOccurred())
			Expect(len(lbtargets.Items)).To(Equal(0))

			res, err = dpdkClient.DeleteLoadBalancerTarget(ctx, lbtarget.LoadbalancerID, lbtarget.Spec.TargetIP)
			Expect(err).To(HaveOccurred())
			Expect(res.Status.Code).To(Equal(uint32(errors.NOT_FOUND)))

			_, err = dpdkClient.DeleteLoadBalancer(ctx, lb.ID)
			Expect(err).ToNot(HaveOccurred())
		})
	})
})

var _ = Describe("init", Label("init"), func() {
	ctx := context.TODO()

	Context("When using init functions", Ordered, func() {
		var init *api.Initialized
		var res *api.Initialized
		var err error

		It("should initialize successfully", func() {
			init, err = dpdkClient.Initialize(ctx)
			Expect(err).ToNot(HaveOccurred())

			Expect(init.Spec.UUID).ToNot(Equal(""))

			// Initializing again should return same UUID
			res, err = dpdkClient.Initialize(ctx)
			Expect(err).ToNot(HaveOccurred())

			Expect(init.Spec.UUID).To(Equal(res.Spec.UUID))
		})

		It("should check if initialized successfully", func() {
			res, err = dpdkClient.CheckInitialized(ctx)
			Expect(err).ToNot(HaveOccurred())

			Expect(res.Spec.UUID).To(Equal(init.Spec.UUID))
		})

		It("should get version successfully", func() {
			clientVersion := api.Version{
				VersionMeta: api.VersionMeta{
					ClientProtocol: "0.0.1",
					ClientName:     "testClient",
					ClientVersion:  "0.0.1"},
			}
			version, err := dpdkClient.GetVersion(ctx, &clientVersion)
			Expect(err).ToNot(HaveOccurred())

			Expect(version.ClientName).To(Equal("testClient"))
			Expect(version.Spec.ServiceProtocol).ToNot(Equal(""))
			Expect(version.Spec.ServiceVersion).ToNot(Equal(""))
		})
	})
})

var _ = Describe("negative interface tests", Label("negative"), func() {
	ctx := context.TODO()
	var iface api.Interface

	BeforeEach(func() {
		ipv4 := netip.MustParseAddr("10.200.1.4")
		ipv6 := netip.MustParseAddr("2000:200:1::4")
		iface = api.Interface{
			InterfaceMeta: api.InterfaceMeta{
				ID: negativeTestIfaceID,
			},
			Spec: api.InterfaceSpec{
				IPv4:   &ipv4,
				IPv6:   &ipv6,
				VNI:    negativeTestVNI,
				Device: "net_tap4",
			},
		}
	})

	Context("When creating and IPv4 is nil", func() {
		It("should not create", func() {
			iface.Spec.IPv4 = nil
			_, err := dpdkClient.CreateInterface(ctx, &iface)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("rpc error: code = InvalidArgument desc = Invalid ipv4_config.primary_address"))
		})
	})

	Context("When creating and IPv6 is nil", func() {
		It("should not create", func() {
			iface.Spec.IPv6 = nil
			_, err := dpdkClient.CreateInterface(ctx, &iface)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("rpc error: code = InvalidArgument desc = Invalid ipv6_config.primary_address"))
		})
	})

	Context("When creating and Device is empty", func() {
		It("should not create", func() {
			iface.Spec.Device = ""
			_, err := dpdkClient.CreateInterface(ctx, &iface)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("rpc error: code = InvalidArgument desc = Invalid device_name"))
		})
	})

	Context("When creating and ID is empty", func() {
		It("should not create", func() {
			iface.ID = ""
			_, err := dpdkClient.CreateInterface(ctx, &iface)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("rpc error: code = InvalidArgument desc = Invalid interface_id"))
		})
	})
})

var _ = Describe("negative interface related tests", Label("negative"), func() {
	ctx := context.TODO()

	// Creates the network interface
	// OncePerOrdered decorator will run this only once per Ordered spec and not before every It spec
	BeforeEach(OncePerOrdered, func() {
		ipv4 := netip.MustParseAddr("10.200.1.4")
		ipv6 := netip.MustParseAddr("2000:200:1::4")
		iface := api.Interface{
			InterfaceMeta: api.InterfaceMeta{
				ID: negativeTestIfaceID,
			},
			Spec: api.InterfaceSpec{
				IPv4:   &ipv4,
				IPv6:   &ipv6,
				VNI:    negativeTestVNI,
				Device: "net_tap4",
			},
		}
		_, err := dpdkClient.CreateInterface(ctx, &iface)
		Expect(err).ToNot(HaveOccurred())

		// Deletes the network interface after spec is completed
		DeferCleanup(func(ctx SpecContext) {
			_, err := dpdkClient.DeleteInterface(ctx, negativeTestIfaceID)
			Expect(err).ToNot(HaveOccurred())
		})
	})

	Context("When using prefix functions", Label("prefix"), Ordered, func() {
		var res *api.Prefix
		var err error

		It("should not create", func() {
			By("not defining IP prefix")
			prefix := api.Prefix{
				PrefixMeta: api.PrefixMeta{
					InterfaceID: negativeTestIfaceID,
				},
				Spec: api.PrefixSpec{},
			}

			res, err = dpdkClient.CreatePrefix(ctx, &prefix)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("rpc error: code = InvalidArgument desc = Invalid prefix.ip"))

			By("not defining InterfaceID")
			prefix.InterfaceID = ""
			prefix.Spec.Prefix = netip.MustParsePrefix("10.20.30.0/24")
			res, err = dpdkClient.CreatePrefix(ctx, &prefix)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("rpc error: code = InvalidArgument desc = Invalid interface_id"))

			By("using non-existent interfaceID")
			prefix.InterfaceID = "xxx"
			res, err = dpdkClient.CreatePrefix(ctx, &prefix)
			Expect(err).To(HaveOccurred())
			Expect(res.InterfaceID).To(Equal("xxx"))
			Expect(res.Status.Code).To(Equal(uint32(errors.NO_VM)))
		})
	})

	Context("When using loadbalancerprefix functions", Label("lbprefix"), Ordered, func() {
		var res *api.LoadBalancerPrefix
		var err error

		It("should not create", func() {
			By("not defining IP prefix")
			lbprefix := api.LoadBalancerPrefix{
				LoadBalancerPrefixMeta: api.LoadBalancerPrefixMeta{
					InterfaceID: negativeTestIfaceID,
				},
				Spec: api.LoadBalancerPrefixSpec{},
			}

			_, err = dpdkClient.CreateLoadBalancerPrefix(ctx, &lbprefix)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("rpc error: code = InvalidArgument desc = Invalid prefix.ip"))

			By("not defining InterfaceID")
			lbprefix.InterfaceID = ""
			lbprefix.Spec.Prefix = netip.MustParsePrefix("10.10.10.0/24")
			_, err = dpdkClient.CreateLoadBalancerPrefix(ctx, &lbprefix)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("rpc error: code = InvalidArgument desc = Invalid interface_id"))

			By("using non-existent interfaceID")
			lbprefix.InterfaceID = "xxx"
			res, err = dpdkClient.CreateLoadBalancerPrefix(ctx, &lbprefix)
			Expect(err).To(HaveOccurred())
			Expect(res.InterfaceID).To(Equal("xxx"))
			Expect(res.Status.Code).To(Equal(uint32(errors.NO_VM)))
		})
	})

	Context("When using virtualIP functions", Label("vip"), Ordered, func() {
		var res *api.VirtualIP
		var err error

		It("should not create", func() {
			By("not defining IP")
			vip := api.VirtualIP{
				VirtualIPMeta: api.VirtualIPMeta{
					InterfaceID: negativeTestIfaceID,
				},
				Spec: api.VirtualIPSpec{},
			}
			_, err = dpdkClient.CreateVirtualIP(ctx, &vip)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("rpc error: code = InvalidArgument desc = Invalid vip_ip"))

			By("not defining InterfaceID")
			ip := netip.MustParseAddr("20.20.20.20")
			vip.Spec.IP = &ip
			vip.InterfaceID = ""
			_, err = dpdkClient.CreateVirtualIP(ctx, &vip)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("rpc error: code = InvalidArgument desc = Invalid interface_id"))

			By("using non-existent interfaceID")
			vip.InterfaceID = "xxx"
			res, err = dpdkClient.CreateVirtualIP(ctx, &vip)
			Expect(err).To(HaveOccurred())
			Expect(res.InterfaceID).To(Equal("xxx"))
			Expect(res.Status.Code).To(Equal(uint32(errors.NO_VM)))
		})
	})

	Context("When using nat functions", Label("nat"), Ordered, func() {
		var res *api.Nat
		var err error

		It("should not create", func() {
			By("not defining port range")
			ip := netip.MustParseAddr("10.20.30.40")
			nat := api.Nat{
				NatMeta: api.NatMeta{
					InterfaceID: negativeTestIfaceID,
				},
				Spec: api.NatSpec{
					NatIP: &ip,
				},
			}

			_, err = dpdkClient.CreateNat(ctx, &nat)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("rpc error: code = InvalidArgument desc = Invalid port range"))

			By("not defining InterfaceID")
			nat.Spec.MinPort = 30000
			nat.Spec.MaxPort = 31000
			nat.NatMeta = api.NatMeta{}
			_, err = dpdkClient.CreateNat(ctx, &nat)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("rpc error: code = InvalidArgument desc = Invalid interface_id"))

			By("MaxPort out of range")
			nat.Spec.MaxPort = 75000
			nat.InterfaceID = negativeTestIfaceID
			_, err = dpdkClient.CreateNat(ctx, &nat)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("rpc error: code = InvalidArgument desc = Invalid max_port"))

			By("MaxPort < MinPort")
			nat.Spec.MinPort = 31000
			nat.Spec.MaxPort = 30000
			_, err = dpdkClient.CreateNat(ctx, &nat)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("rpc error: code = InvalidArgument desc = Invalid port range"))

			By("not defining IP")
			nat.Spec.NatIP = nil
			_, err = dpdkClient.CreateNat(ctx, &nat)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("rpc error: code = InvalidArgument desc = Invalid nat_ip"))

			By("using non-existent interfaceID")
			nat.Spec.NatIP = &ip
			nat.InterfaceID = "xxx"
			nat.Spec.MinPort = 30000
			nat.Spec.MaxPort = 31000
			res, err = dpdkClient.CreateNat(ctx, &nat)
			Expect(err).To(HaveOccurred())
			Expect(res.InterfaceID).To(Equal("xxx"))
			Expect(res.Status.Code).To(Equal(uint32(errors.NO_VM)))
		})
	})

	Context("When using neighbor nat functions", Label("neighbornat"), Ordered, func() {
		var neighborNat api.NeighborNat
		var err error

		It("should not create", func() {
			By("not defining nat IP")

			underlayRoute := netip.MustParseAddr("ff80::1")
			neighborNat = api.NeighborNat{
				NeighborNatMeta: api.NeighborNatMeta{},
				Spec: api.NeighborNatSpec{
					Vni:           100,
					MinPort:       30000,
					MaxPort:       30100,
					UnderlayRoute: &underlayRoute,
				},
			}

			_, err = dpdkClient.CreateNeighborNat(ctx, &neighborNat)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("rpc error: code = InvalidArgument desc = Invalid nat_ip"))

			By("not defining UnderlayRoute")
			neighborNat.Spec.UnderlayRoute = nil
			_, err = dpdkClient.CreateNeighborNat(ctx, &neighborNat)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("underlayRoute needs to be specified"))

			By("MaxPort < MinPort")
			natIp := netip.MustParseAddr("10.20.30.40")
			neighborNat.NatIP = &natIp
			neighborNat.Spec.MinPort = 31000
			neighborNat.Spec.MaxPort = 30000
			neighborNat.Spec.UnderlayRoute = &underlayRoute
			_, err = dpdkClient.CreateNeighborNat(ctx, &neighborNat)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("rpc error: code = InvalidArgument desc = Invalid port range"))

			By("not defining Spec")
			neighborNat.Spec = api.NeighborNatSpec{}
			_, err = dpdkClient.CreateNeighborNat(ctx, &neighborNat)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("underlayRoute needs to be specified"))
		})
	})

	Context("When using route functions", Label("route"), Ordered, func() {
		var route api.Route
		var res *api.Route
		var err error

		It("should not create", func() {
			By("not defining VNI")
			prefix := netip.MustParsePrefix("10.100.3.0/24")
			nextHopIp := netip.MustParseAddr("fc00:2::64:0:1")
			route = api.Route{
				RouteMeta: api.RouteMeta{},
				Spec: api.RouteSpec{
					Prefix: &prefix,
					NextHop: &api.RouteNextHop{
						VNI: 0,
						IP:  &nextHopIp,
					},
				},
			}
			res, err = dpdkClient.CreateRoute(ctx, &route)
			Expect(err).To(HaveOccurred())
			Expect(res.Status.Code).To(Equal(uint32(errors.NO_VNI)))

			By("not defining prefix")
			route.VNI = negativeTestVNI
			route.Spec.Prefix = nil
			_, err = dpdkClient.CreateRoute(ctx, &route)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("prefix needs to be specified"))

			By("not defining nexthop ip")
			route.Spec.Prefix = &prefix
			route.Spec.NextHop.IP = nil
			_, err = dpdkClient.CreateRoute(ctx, &route)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("rpc error: code = InvalidArgument desc = Invalid route.nexthop_address"))

			By("not defining nexthop")
			route.Spec.NextHop = nil
			_, err = dpdkClient.CreateRoute(ctx, &route)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("nextHop needs to be specified"))
		})
	})

	Context("When using firewall rule functions", Label("fwrule"), Ordered, func() {
		var fwRule api.FirewallRule
		var err error

		It("should not create", func() {
			By("not defining InterfaceID")
			src := netip.MustParsePrefix("1.1.1.1/32")
			dst := netip.MustParsePrefix("5.5.5.0/24")
			fwRule = api.FirewallRule{
				FirewallRuleMeta: api.FirewallRuleMeta{},
				Spec: api.FirewallRuleSpec{
					RuleID:            "Rule1",
					TrafficDirection:  "ingress",
					FirewallAction:    "accept",
					Priority:          1000,
					SourcePrefix:      &src,
					DestinationPrefix: &dst,
					ProtocolFilter: &dpdkproto.ProtocolFilter{
						Filter: &dpdkproto.ProtocolFilter_Tcp{
							Tcp: &dpdkproto.TcpFilter{
								SrcPortLower: 1,
								SrcPortUpper: 65535,
								DstPortLower: 500,
								DstPortUpper: 600,
							},
						},
					},
				},
			}

			_, err = dpdkClient.CreateFirewallRule(ctx, &fwRule)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("rpc error: code = InvalidArgument desc = Invalid interface_id"))

			By("empty ruleID")
			fwRule.InterfaceID = negativeTestIfaceID
			fwRule.Spec.RuleID = ""
			_, err = dpdkClient.CreateFirewallRule(ctx, &fwRule)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("rpc error: code = InvalidArgument desc = Invalid rule id"))

			By("wrong traffic direction")
			fwRule.Spec.RuleID = "Rule1"
			fwRule.Spec.TrafficDirection = "xxx"
			_, err = dpdkClient.CreateFirewallRule(ctx, &fwRule)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("traffic direction can be only: Ingress = 0/Egress = 1"))

			By("wrong fw action")
			fwRule.Spec.TrafficDirection = "ingress"
			fwRule.Spec.FirewallAction = "xxx"
			_, err = dpdkClient.CreateFirewallRule(ctx, &fwRule)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("firewall action can be only: drop/deny/0|accept/allow/1"))

			By("not defining src prefix")
			fwRule.Spec.FirewallAction = "accept"
			fwRule.Spec.SourcePrefix = nil
			_, err = dpdkClient.CreateFirewallRule(ctx, &fwRule)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("source prefix needs to be specified"))

			By("not defining dst prefix")
			fwRule.Spec.SourcePrefix = &src
			fwRule.Spec.DestinationPrefix = nil
			_, err = dpdkClient.CreateFirewallRule(ctx, &fwRule)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("destination prefix needs to be specified"))

			By("srcportlower out of range")
			fwRule.Spec.DestinationPrefix = &dst
			fwRule.Spec.ProtocolFilter.Filter = &dpdkproto.ProtocolFilter_Tcp{
				Tcp: &dpdkproto.TcpFilter{
					SrcPortLower: -5,
				},
			}
			_, err = dpdkClient.CreateFirewallRule(ctx, &fwRule)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("rpc error: code = InvalidArgument desc = Invalid tcp.src_port_lower"))

			By("srcportupper out of range")
			fwRule.Spec.ProtocolFilter.Filter = &dpdkproto.ProtocolFilter_Tcp{
				Tcp: &dpdkproto.TcpFilter{
					SrcPortUpper: 75000,
				},
			}
			_, err = dpdkClient.CreateFirewallRule(ctx, &fwRule)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("rpc error: code = InvalidArgument desc = Invalid tcp.src_port_upper"))

			By("dstportupper > dstportlower")
			fwRule.Spec.ProtocolFilter.Filter = &dpdkproto.ProtocolFilter_Udp{
				Udp: &dpdkproto.UdpFilter{
					DstPortLower: 500,
					DstPortUpper: 400,
				},
			}
			_, err = dpdkClient.CreateFirewallRule(ctx, &fwRule)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("rpc error: code = InvalidArgument desc = Invalid udp.dst_port range"))

			By("icmpType out of range")
			fwRule.Spec.ProtocolFilter.Filter = &dpdkproto.ProtocolFilter_Icmp{
				Icmp: &dpdkproto.IcmpFilter{
					IcmpType: -5,
				},
			}
			_, err = dpdkClient.CreateFirewallRule(ctx, &fwRule)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("rpc error: code = InvalidArgument desc = Invalid icmp.icmp_type"))

			By("icmpCode out of range")
			fwRule.Spec.ProtocolFilter.Filter = &dpdkproto.ProtocolFilter_Icmp{
				Icmp: &dpdkproto.IcmpFilter{
					IcmpCode: 400,
				},
			}
			_, err = dpdkClient.CreateFirewallRule(ctx, &fwRule)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("rpc error: code = InvalidArgument desc = Invalid icmp.icmp_code"))

			By("not defining spec")
			fwRule.Spec = api.FirewallRuleSpec{}
			_, err = dpdkClient.CreateFirewallRule(ctx, &fwRule)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("firewall action can be only: drop/deny/0|accept/allow/1"))
		})
	})

	Context("When using capture functions", Label("capture"), Ordered, func() {
		var res *api.CaptureStatus
		var err error
		sinkNode := netip.MustParseAddr("fc00:2::64:0:1")
		captureStart := api.CaptureStart{
			CaptureStartMeta: api.CaptureStartMeta{
				Config: &api.CaptureConfig{
					UdpSrcPort: 500,
					UdpDstPort: 1000,
				},
			},
			Spec: api.CaptureStartSpec{
				Interfaces: []api.CaptureInterface{
					{
						InterfaceType: "vf",
						InterfaceInfo: negativeTestIfaceID,
					},
				},
			},
		}

		It("should return empty capture", func() {
			By("no running capture")
			res, err = dpdkClient.CaptureStatus(ctx)
			Expect(err).ToNot(HaveOccurred())

			Expect(res.Spec.OperationStatus).To(Equal(false))
			Expect(res.Spec.Config.SinkNodeIP).To(BeNil())
		})

		It("should return error", func() {
			By("not defining sink node")
			_, err := dpdkClient.CaptureStart(ctx, &captureStart)

			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("rpc error: code = InvalidArgument desc = Invalid sink_node_ip"))

			By("using ipv4 sink node")
			addr := netip.MustParseAddr("10.0.0.1")
			captureStart.Config.SinkNodeIP = &addr
			_, err = dpdkClient.CaptureStart(ctx, &captureStart)

			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("rpc error: code = InvalidArgument desc = Invalid sink_node_ip"))

			By("not defining capture config")
			captureStart.Config = &api.CaptureConfig{}
			_, err = dpdkClient.CaptureStart(ctx, &captureStart)

			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("rpc error: code = InvalidArgument desc = Invalid sink_node_ip"))

			By("src port out of range")
			captureStart.Config.SinkNodeIP = &sinkNode
			captureStart.CaptureStartMeta.Config.UdpSrcPort = 70000

			_, err = dpdkClient.CaptureStart(ctx, &captureStart)

			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("rpc error: code = InvalidArgument desc = Invalid udp_src_port"))

			By("dst port out of range")
			captureStart.CaptureStartMeta.Config.UdpSrcPort = 500
			captureStart.CaptureStartMeta.Config.UdpDstPort = 70000

			_, err = dpdkClient.CaptureStart(ctx, &captureStart)

			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("rpc error: code = InvalidArgument desc = Invalid udp_dst_port"))

			By("stopping when no capture is running")
			_, err = dpdkClient.CaptureStop(ctx)

			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("[error code 211] NOT_ACTIVE"))
		})
	})
})
