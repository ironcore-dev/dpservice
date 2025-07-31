# SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and IronCore contributors
# SPDX-License-Identifier: Apache-2.0

import pytest

from config import *
from helpers import *


#
# VM-VM traffic on the same host
# should work even without connection tracking as both VMs are local
#
def local_vf_to_vf_responder(vm, dp_service_b):
	pkt = sniff_packet(vm.tap, is_udp_pkt)
	reply_pkt = (Ether(dst=pkt[Ether].src, src=pkt[Ether].dst, type=0x0800) /
				 IP(dst=pkt[IP].src, src=pkt[IP].dst) /
				 UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport))
	# "crash" the first dpservice and send reply to the other one
	dp_service_b.become_active()
	delayed_sendp(reply_pkt, vm.tap_b)

def test_ha_vm_vm_local(prepare_ifaces, prepare_ifaces_b, dp_service_b):
	threading.Thread(target=local_vf_to_vf_responder, args=(VM2, dp_service_b)).start()

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
def cross_vf_to_vf_responder(pf, dst_vm, dp_service_b):
	pkt = sniff_packet(pf.tap, is_udp_pkt)
	assert pkt[IPv6].src == dst_vm.ul_ipv6, \
		"Packet not from the right VM"
	# "crash" the first dpservice and send reply to the other one
	dp_service_b.become_active()
	# NOTE: in pytest the underlay address is different as it is easier, in reality it will be the same
	reply_pkt = (Ether(dst=pkt[Ether].src, src=pkt[Ether].dst, type=0x86DD) /
				 IPv6(dst=dst_vm.ul_ipv6_b, src=pkt[IPv6].dst) /
				 IP(dst=pkt[IP].src, src=pkt[IP].dst) /
				 UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport))
	delayed_sendp(reply_pkt, pf.tap_b)

def test_ha_vm_vm_cross(prepare_ifaces, prepare_ifaces_b, dp_service_b):
	threading.Thread(target=cross_vf_to_vf_responder, args=(PF0, VM1, dp_service_b)).start()

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
def test_ha_vm_public(prepare_ifaces, prepare_ifaces_b, dp_service_b):
	threading.Thread(target=cross_vf_to_vf_responder, args=(PF0, VM1, dp_service_b)).start()

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
def vip_responder(src_tap, dst_tap, dp_service_b):
	pkt = sniff_packet(src_tap, is_udp_pkt)
	reply_pkt = (Ether(dst=pkt[Ether].src, src=pkt[Ether].dst, type=0x0800) /
				 IP(dst=pkt[IP].src, src=pkt[IP].dst) /
				 UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport))
	# "crash" the first dpservice and send reply to the other one
	dp_service_b.become_active()
	delayed_sendp(reply_pkt, dst_tap)

def vip_traffic(ul, ip, req_pf_tap, req_vm_tap, rep_pf_tap, rep_vm_tap, rep_vm_ul, dp_service_b):
	threading.Thread(target=vip_responder, args=(req_vm_tap, rep_vm_tap, dp_service_b)).start()

	pkt = (Ether(dst=PF0.mac, src=PF0.mac, type=0x86DD) /
		   IPv6(dst=ul, src=router_ul_ipv6, nh=4) /
		   IP(dst=ip, src=public_ip) /
		   UDP(dport=1234))
	delayed_sendp(pkt, req_pf_tap)

	# Sniff the other dpservice
	reply = sniff_packet(rep_pf_tap, is_udp_pkt)
	assert reply[IPv6].src == rep_vm_ul, \
		"Invalid reply VNF"

def test_ha_vip(prepare_ifaces, prepare_ifaces_b, grpc_client, grpc_client_b, dp_service_b):
	vip_ul = grpc_client.addvip(VM1.name, vip_vip)
	vip_ul_b = grpc_client_b.addvip(VM1.name, vip_vip)
	vip_traffic(vip_ul, vip_vip, PF0.tap, VM1.tap, PF0.tap_b, VM1.tap_b, VM1.ul_ipv6_b, dp_service_b)
	grpc_client_b.delvip(VM1.name)
	grpc_client.delvip(VM1.name)


#
# public-LB traffic
# should work even without connection tracking due to the nature of LB
# (this is basically another VIP)
#
def test_ha_lb(prepare_ifaces, prepare_ifaces_b, grpc_client, grpc_client_b, dp_service_b):
	lb_ul = grpc_client.createlb(lb_name, vni1, lb_ip, "udp/1234")
	lb_ul_b = grpc_client_b.createlb(lb_name, vni1, lb_ip, "udp/1234")
	lbpfx_ul = grpc_client.addlbprefix(VM1.name, lb_pfx)
	lbpfx_ul_b = grpc_client_b.addlbprefix(VM1.name, lb_pfx)
	grpc_client.addlbtarget(lb_name, lbpfx_ul)
	grpc_client_b.addlbtarget(lb_name, lbpfx_ul_b)
	vip_traffic(lb_ul, lb_ip, PF0.tap, VM1.tap, PF0.tap_b, VM1.tap_b, VM1.ul_ipv6_b, dp_service_b)
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

def test_ha_maglev(prepare_ifaces, prepare_ifaces_b, grpc_client, grpc_client_b, dp_service_b):
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

	# In this test only LB targeting is tested, both dpservice can run as active at once
	dp_service_b.become_active()

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
def nat_responder(pf_tap, nat_ul, dp_service_b, icmp=False):
	pkt = sniff_packet(pf_tap, is_icmp_pkt if icmp else is_udp_pkt)
	assert pkt[IP].src == nat_vip, \
		"Packet not from NAT"
	# "crash" the first dpservice and send reply to the other one
	if dp_service_b:
		dp_service_b.become_active()
	if icmp:
		payload = ICMP(type=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq)
	else:
		payload = UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport)
	reply_pkt = (Ether(dst=pkt[Ether].src, src=pkt[Ether].dst, type=0x86DD) /
				 IPv6(dst=nat_ul, src=pkt[IPv6].dst) /
				 IP(dst=pkt[IP].src, src=pkt[IP].dst) /
				 payload)
	delayed_sendp(reply_pkt, PF0.tap_b)

def nat_communicate(pf_tap, vm_tap, nat_ul, dp_service_b, icmp, ipv6):
	threading.Thread(target=nat_responder, args=(pf_tap, nat_ul, dp_service_b, icmp)).start()

	if ipv6:
		l3 = IPv6(dst=public_nat64_ipv6, src=VM1.ipv6)
		payload = ICMPv6EchoRequest(id=0x0040, seq=123) if icmp else UDP(dport=1234)
	else:
		l3 = IP(dst=public_ip, src=VM1.ip)
		payload = ICMP(type=8, id=0x0040, seq=123) if icmp else UDP(dport=1234)
	pkt = Ether(dst=PF0.mac, src=VM1.mac) / l3 / payload
	delayed_sendp(pkt, vm_tap)

	# Sniff the other dpservice
	lfilter = (is_icmpv6echo_reply_pkt if ipv6 else is_icmp_pkt) if icmp else is_udp_pkt
	reply = sniff_packet(VM1.tap_b, lfilter)
	if ipv6:
		assert reply[IPv6].dst == pkt[IPv6].src, \
			"Reply not to the right address"
	else:
		assert reply[IP].dst == pkt[IP].src, \
			"Reply not to the right address"
	if icmp:
		reply_id = reply[ICMPv6EchoReply].id if ipv6 else reply[ICMP].id
		reply_seq = reply[ICMPv6EchoReply].seq if ipv6 else reply[ICMP].seq
		assert reply_id == 0x0040, \
			"Reply does not use the right id"
		assert reply_seq == 123, \
			"Reply does not use the right seq number"
	else:
		assert reply[UDP].dport == pkt[UDP].sport, \
			"Reply not to the right port"

def nat_test_handover(grpc_client, grpc_client_b, dp_service_b, icmp=False, ipv6=False):
	nat_ul = grpc_client.addnat(VM1.name, nat_vip, nat_local_min_port, nat_local_max_port)
	nat_ul_b = grpc_client_b.addnat(VM1.name, nat_vip, nat_local_min_port, nat_local_max_port)

	# First, send packet to primary, activate backup, sniff backup
	nat_communicate(PF0.tap, VM1.tap, nat_ul_b, dp_service_b, icmp, ipv6)

	# Second, send packet to backup and sniff it
	nat_communicate(PF0.tap_b, VM1.tap_b, nat_ul_b, None, icmp, ipv6)

	grpc_client_b.delnat(VM1.name)
	grpc_client.delnat(VM1.name)

def test_ha_vm_nat(prepare_ifaces, prepare_ifaces_b, grpc_client, grpc_client_b, dp_service_b):
	nat_test_handover(grpc_client, grpc_client_b, dp_service_b)

def test_ha_vm_nat_icmp(prepare_ifaces, prepare_ifaces_b, grpc_client, grpc_client_b, dp_service_b):
	nat_test_handover(grpc_client, grpc_client_b, dp_service_b, icmp=True)

def test_ha_vm_nat64(prepare_ifaces, prepare_ifaces_b, grpc_client, grpc_client_b, dp_service_b):
	# TODO this only works when code changes to use nat64 addr
	nat_test_handover(grpc_client, grpc_client_b, dp_service_b, ipv6=True)

def test_ha_vm_nat64_icmp(prepare_ifaces, prepare_ifaces_b, grpc_client, grpc_client_b, dp_service_b):
	# TODO this only works when code changes to use nat64 addr
	# TODO there is a bug in flow itself, though test is working
	nat_test_handover(grpc_client, grpc_client_b, dp_service_b, ipv6=True, icmp=True)

# TODO some test to utilize flow aging?
	# age_out_flows()


#
# Virtual Service traffic
# this also needs synchronization:
#  - packet leaves VM though virstvc-NAT -> creates virstvc-NAT table entries in dpservice
#  - packet comes back to the second dpservice that lacks these entries -> DROP
# (this is the exact same situation as NAT, just for virtual services - separate codepath)
#
def virtsvc_responder(dp_service_b):
	pkt = sniff_packet(PF0.tap, is_udp_pkt)
	assert pkt[IPv6].dst == virtsvc_udp_svc_ipv6, \
		"Request to wrong IPv6 address"
	assert pkt[UDP].dport == virtsvc_udp_svc_port, \
		"Request to wrong UDP port"
	# TODO send to the other dpservice - THIS WILL FAIL!!
	# TODO and it also has a different underlay address!
	# "crash" the first dpservice and send reply to the other one
	dp_service_b.become_active()
	reply_pkt = (Ether(dst=pkt[Ether].src, src=pkt[Ether].dst, type=0x86DD) /
				 IPv6(dst=pkt[IPv6].src, src=pkt[IPv6].dst, nh=17) /
				 UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport))
	delayed_sendp(reply_pkt, PF0.tap_b)

def test_ha_virtsvc(request, prepare_ifaces, prepare_ifaces_b, dp_service_b):
	if not request.config.getoption("--virtsvc"):
		pytest.skip("Virtual services not enabled")

	threading.Thread(target=virtsvc_responder, args=(dp_service_b,)).start()

	pkt = (Ether(dst=VM1.mac, src=VM1.mac, type=0x0800) /
		   IP(dst=virtsvc_udp_virtual_ip, src=VM1.ip) /
		   UDP(dport=virtsvc_udp_virtual_port, sport=1234))
	delayed_sendp(pkt, VM1.tap)

	# Sniff the other dpservice
	reply = sniff_packet(VM1.tap_b, is_udp_pkt)
	reply.show()
	assert reply[IP].src == virtsvc_udp_virtual_ip, \
		"Got answer from wrong UDP source port"
	assert reply[UDP].sport == virtsvc_udp_virtual_port, \
		"Got answer from wrong UDP source port"
	assert reply[UDP].dport == 1234, \
		"Got answer to wrong UDP destination port"


#
# There is no need to test packet_relay mechanism
# because by design it accepts outside packets and relays them somewhere
# there is nothing extra to keep track of, it is driven directly by LB/VNF tables
#
