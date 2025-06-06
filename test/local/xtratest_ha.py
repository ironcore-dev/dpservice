# SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and IronCore contributors
# SPDX-License-Identifier: Apache-2.0

import pytest

from config import *
from helpers import *


#
# VM-VM traffic on the same host
# should work even without connection tracking as both VMs are local
#
def local_vf_to_vf_responder(vm):
	pkt = sniff_packet(vm.tap, is_udp_pkt)
	reply_pkt = (Ether(dst=pkt[Ether].src, src=pkt[Ether].dst, type=0x0800) /
				 IP(dst=pkt[IP].src, src=pkt[IP].dst) /
				 UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport))
	# Send it back to the other dpservice
	delayed_sendp(reply_pkt, vm.tap_b)

def test_ha_vm_vm_local(prepare_ifaces, prepare_ifaces_b):
	threading.Thread(target=local_vf_to_vf_responder, args=(VM2,)).start()

	pkt = (Ether(dst=VM2.mac, src=VM1.mac, type=0x0800) /
		   IP(dst=VM2.ip, src=VM1.ip) /
		   UDP(dport=1234))
	delayed_sendp(pkt, VM1.tap)

	# Sniff the other dpservice
	sniff_packet(VM1.tap_b, is_udp_pkt)


#
# VM-VM traffic across hosts (dpservices)
# should work even without connection tracking due to routes being there
#
def cross_vf_to_vf_responder(pf, dst_vm):
	pkt = sniff_packet(pf.tap, is_udp_pkt)
	assert pkt[IPv6].src == dst_vm.ul_ipv6, \
		"Packet not from the right VM"
	# Send it back to the other dpservice (different underlay address)
	reply_pkt = (Ether(dst=pkt[Ether].src, src=pkt[Ether].dst, type=0x86DD) /
				 IPv6(dst=dst_vm.ul_ipv6_b, src=pkt[IPv6].dst) /
				 IP(dst=pkt[IP].src, src=pkt[IP].dst) /
				 UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport))
	delayed_sendp(reply_pkt, pf.tap_b)

def test_ha_vm_vm_cross(prepare_ifaces, prepare_ifaces_b):
	threading.Thread(target=cross_vf_to_vf_responder, args=(PF0, VM1)).start()

	pkt = (Ether(dst=PF0.mac, src=VM1.mac, type=0x0800) /
		   IP(dst=f"{neigh_vni1_ov_ip_prefix}.1", src=VM1.ip) /
		   UDP(dport=1234))
	delayed_sendp(pkt, VM1.tap)

	# Sniff the other dpservice
	sniff_packet(VM1.tap_b, is_udp_pkt)


#
# VM-public traffic
# should work even without connection tracking due to default route to router
# (in reality this packet gets dropped on the way out to the internet)
#
def test_ha_vm_public(prepare_ifaces, prepare_ifaces_b):
	threading.Thread(target=cross_vf_to_vf_responder, args=(PF0, VM1)).start()

	pkt = (Ether(dst=PF0.mac, src=VM1.mac, type=0x0800) /
		   IP(dst=public_ip, src=VM1.ip) /
		   UDP(dport=1234))
	delayed_sendp(pkt, VM1.tap)

	# Sniff the other dpservice
	sniff_packet(VM1.tap_b, is_udp_pkt)


#
# public-VIP traffic
# should work even without connection tracking due to the nature of VIP
#
def vip_responder(src_tap, dst_tap):
	pkt = sniff_packet(src_tap, is_udp_pkt)
	reply_pkt = (Ether(dst=pkt[Ether].src, src=pkt[Ether].dst, type=0x0800) /
				 IP(dst=pkt[IP].src, src=pkt[IP].dst) /
				 UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport))
	# Send it out through the other dpservice
	delayed_sendp(reply_pkt, dst_tap)

def vip_traffic(ul, ip, req_pf_tap, req_vm_tap, rep_pf_tap, rep_vm_tap, rep_vm_ul):
	threading.Thread(target=vip_responder, args=(req_vm_tap, rep_vm_tap)).start()

	pkt = (Ether(dst=PF0.mac, src=PF0.mac, type=0x86DD) /
		   IPv6(dst=ul, src=router_ul_ipv6, nh=4) /
		   IP(dst=ip, src=public_ip) /
		   UDP(dport=1234))
	delayed_sendp(pkt, req_pf_tap)

	# Sniff the other dpservice
	reply = sniff_packet(rep_pf_tap, is_udp_pkt)
	assert reply[IPv6].src == rep_vm_ul, \
		"Invalid reply VNF"

def test_ha_vip(prepare_ifaces, prepare_ifaces_b, grpc_client, grpc_client_b):
	vip_ul = grpc_client.addvip(VM1.name, vip_vip)
	vip_ul_b = grpc_client_b.addvip(VM1.name, vip_vip)
	vip_traffic(vip_ul, vip_vip, PF0.tap, VM1.tap, PF0.tap_b, VM1.tap_b, VM1.ul_ipv6_b)
	vip_traffic(vip_ul_b, vip_vip, PF0.tap_b, VM1.tap_b, PF0.tap, VM1.tap, VM1.ul_ipv6)
	grpc_client_b.delvip(VM1.name)
	grpc_client.delvip(VM1.name)


#
# public-LB traffic
# should work even without connection tracking due to the nature of LB
# (this is basically another VIP)
#
def test_ha_lb(prepare_ifaces, prepare_ifaces_b, grpc_client, grpc_client_b):
	lb_ul = grpc_client.createlb(lb_name, vni1, lb_ip, "udp/1234")
	lb_ul_b = grpc_client_b.createlb(lb_name, vni1, lb_ip, "udp/1234")
	lbpfx_ul = grpc_client.addlbprefix(VM1.name, lb_pfx)
	lbpfx_ul_b = grpc_client_b.addlbprefix(VM1.name, lb_pfx)
	grpc_client.addlbtarget(lb_name, lbpfx_ul)
	grpc_client_b.addlbtarget(lb_name, lbpfx_ul_b)
	vip_traffic(lb_ul, lb_ip, PF0.tap, VM1.tap, PF0.tap_b, VM1.tap_b, VM1.ul_ipv6_b)
	grpc_client_b.dellbtarget(lb_name, lbpfx_ul_b)
	grpc_client_b.dellbprefix(VM1.name, lb_pfx)
	grpc_client_b.dellb(lb_name)
	grpc_client.dellbtarget(lb_name, lbpfx_ul)
	grpc_client.dellbprefix(VM1.name, lb_pfx)
	grpc_client.dellb(lb_name)


#
# Incoming traffic to a loadbalancer
# should select the same target VM if addresses/ports are the same
#
def maglev_checker(dst_tap):
	pkt = sniff_packet(dst_tap, is_udp_pkt)
	assert pkt[IP].dst == lb_ip and pkt[UDP].dport == 1234, \
		"Invalid packet routed to target"
	reply_pkt = (Ether(dst=pkt[Ether].src, src=pkt[Ether].dst, type=0x0800) /
				 IP(dst=pkt[IP].src, src=pkt[IP].dst) /
				 UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport))
	delayed_sendp(reply_pkt, dst_tap)

def send_lb_udp(lb_ul, tap, target_tap, ip, port):
	threading.Thread(target=maglev_checker, args=(target_tap,)).start()
	pkt = (Ether(dst=PF0.mac, src=PF0.mac, type=0x86DD) /
		   IPv6(dst=lb_ul, src=router_ul_ipv6, nh=4) /
		   IP(dst=lb_ip, src=ip) /
		   UDP(dport=port))
	delayed_sendp(pkt, tap)
	reply = sniff_packet(tap, is_udp_pkt)
	assert reply[IP].dst == ip and reply[UDP].sport == port, \
		"Invalid reply from target"

def test_ha_maglev(prepare_ifaces, prepare_ifaces_b, grpc_client, grpc_client_b):
	lb_ul = grpc_client.createlb(lb_name, vni1, lb_ip, "udp/1234")
	lb_ul_b = grpc_client_b.createlb(lb_name, vni1, lb_ip, "udp/1234")
	target_vms = (VM1, VM2, VM3)

	for vm in target_vms:
		# Both dpservices need to have the same address for Maglev to work the same
		#  -> needs metalnet-generated underlays
		preferred_ul = "fc00:1::8000:1234:"+vm.name[-1]
		vm._lbpfx_ul = grpc_client.addlbprefix(vm.name, lb_pfx, preferred_underlay=preferred_ul)
		grpc_client.addlbtarget(lb_name, vm._lbpfx_ul)
		vm._lbpfx_ul_b = grpc_client_b.addlbprefix(vm.name, lb_pfx, preferred_underlay=preferred_ul)
		grpc_client_b.addlbtarget(lb_name, vm._lbpfx_ul_b)

	# for the underlay above, public_ip:1234 should go to VM2
	send_lb_udp(lb_ul, PF0.tap, VM2.tap, public_ip, 1234)
	send_lb_udp(lb_ul_b, PF0.tap_b, VM2.tap_b, public_ip, 1234)
	# for the underlay above, public_ip2:1235 should go to VM3
	send_lb_udp(lb_ul, PF0.tap, VM3.tap, public_ip2, 1234)
	send_lb_udp(lb_ul_b, PF0.tap_b, VM3.tap_b, public_ip2, 1234)

	for vm in target_vms:
		grpc_client_b.dellbtarget(lb_name, vm._lbpfx_ul_b)
		grpc_client_b.dellbprefix(vm.name, lb_pfx)
		grpc_client.dellbtarget(lb_name, vm._lbpfx_ul)
		grpc_client.dellbprefix(vm.name, lb_pfx)

	grpc_client_b.dellb(lb_name)
	grpc_client.dellb(lb_name)


#
# VM-NAT-public traffic
# this needs synchronization:
#  - packet leaves VM though NAT -> creates NAT table entries in dpservice
#  - packet comes back to the second dpservice that lacks these entries -> DROP
# (basically the same as VIP, but does not work out of the box)
#
def nat_responder(nat_ul):
	pkt = sniff_packet(PF0.tap, is_udp_pkt)
	assert pkt[IP].src == nat_vip, \
		"Packet not from NAT"
	# Send it to the other dpservice
	reply_pkt = (Ether(dst=pkt[Ether].src, src=pkt[Ether].dst, type=0x86DD) /
				 IPv6(dst=nat_ul, src=pkt[IPv6].dst) /
				 IP(dst=pkt[IP].src, src=pkt[IP].dst) /
				 UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport))
	delayed_sendp(reply_pkt, PF0.tap_b)

def test_ha_vm_nat(prepare_ifaces, prepare_ifaces_b, grpc_client, grpc_client_b):
	nat_ul = grpc_client.addnat(VM1.name, nat_vip, nat_local_min_port, nat_local_max_port)
	nat_ul_b = grpc_client_b.addnat(VM1.name, nat_vip, nat_local_min_port, nat_local_max_port)

	threading.Thread(target=nat_responder, args=(nat_ul_b,)).start()

	pkt = (Ether(dst=PF0.mac, src=VM1.mac, type=0x0800) /
		   IP(dst=public_ip, src=VM1.ip) /
		   UDP(dport=1234))
	delayed_sendp(pkt, VM1.tap)

	# Sniff the other dpservice
	sniff_packet(VM1.tap_b, is_udp_pkt)

	grpc_client_b.delnat(VM1.name)
	grpc_client.delnat(VM1.name)


# TODO others? like private LB, LB-NAT, LB-VIP, etc?

# TODO packet relay!
