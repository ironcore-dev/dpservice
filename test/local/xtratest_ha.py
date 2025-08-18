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
	reply_pkt = (Ether(dst=pkt[Ether].src, src=pkt[Ether].dst) /
				 IP(dst=pkt[IP].src, src=pkt[IP].dst) /
				 UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport))
	# "crash" the first dpservice and send reply to the other one
	dp_service_b.become_active()
	delayed_sendp(reply_pkt, vm.tap_b)

def test_ha_vm_vm_local(prepare_ifaces, prepare_ifaces_b, dp_service_b):
	threading.Thread(target=local_vf_to_vf_responder, args=(VM2, dp_service_b)).start()

	pkt = (Ether(dst=VM2.mac, src=VM1.mac) /
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
	reply_pkt = (Ether(dst=pkt[Ether].src, src=pkt[Ether].dst) /
				 IPv6(dst=dst_vm.ul_ipv6_b, src=pkt[IPv6].dst) /
				 IP(dst=pkt[IP].src, src=pkt[IP].dst) /
				 UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport))
	delayed_sendp(reply_pkt, pf.tap_b)

def test_ha_vm_vm_cross(prepare_ifaces, prepare_ifaces_b, dp_service_b):
	threading.Thread(target=cross_vf_to_vf_responder, args=(PF0, VM1, dp_service_b)).start()

	pkt = (Ether(dst=PF0.mac, src=VM1.mac) /
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

	pkt = (Ether(dst=PF0.mac, src=VM1.mac) /
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
	reply_pkt = (Ether(dst=pkt[Ether].src, src=pkt[Ether].dst) /
				 IP(dst=pkt[IP].src, src=pkt[IP].dst) /
				 UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport))
	# "crash" the first dpservice and send reply to the other one
	dp_service_b.become_active()
	delayed_sendp(reply_pkt, dst_tap)

def vip_traffic(ul, ip, req_pf_tap, req_vm_tap, rep_pf_tap, rep_vm_tap, rep_vm_ul, dp_service_b):
	threading.Thread(target=vip_responder, args=(req_vm_tap, rep_vm_tap, dp_service_b)).start()

	pkt = (Ether(dst=PF0.mac, src=PF0.mac) /
		   IPv6(dst=ul, src=router_ul_ipv6) /
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
	reply_pkt = (Ether(dst=pkt[Ether].src, src=pkt[Ether].dst) /
				 IP(dst=pkt[IP].src, src=pkt[IP].dst) /
				 UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport))
	delayed_sendp(reply_pkt, dst_tap)

def send_lb_udp(lb_ul, tap, target_tap, ip, port):
	threading.Thread(target=maglev_checker, args=(target_tap,)).start()
	pkt = (Ether(dst=PF0.mac, src=PF0.mac) /
		   IPv6(dst=lb_ul, src=router_ul_ipv6) /
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
	reply_pkt = (Ether(dst=pkt[Ether].src, src=pkt[Ether].dst) /
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

	# This is just for manual test - flow aging is verified by another pytest unit already
	# age_out_flows()

	grpc_client_b.delnat(VM1.name)
	grpc_client.delnat(VM1.name)

def test_ha_vm_nat(prepare_ifaces, prepare_ifaces_b, grpc_client, grpc_client_b, dp_service_b):
	nat_test_handover(grpc_client, grpc_client_b, dp_service_b)

def test_ha_vm_nat_icmp(prepare_ifaces, prepare_ifaces_b, grpc_client, grpc_client_b, dp_service_b):
	nat_test_handover(grpc_client, grpc_client_b, dp_service_b, icmp=True)

def test_ha_vm_nat64(prepare_ifaces, prepare_ifaces_b, grpc_client, grpc_client_b, dp_service_b):
	nat_test_handover(grpc_client, grpc_client_b, dp_service_b, ipv6=True)

def test_ha_vm_nat64_icmp(prepare_ifaces, prepare_ifaces_b, grpc_client, grpc_client_b, dp_service_b):
	nat_test_handover(grpc_client, grpc_client_b, dp_service_b, ipv6=True, icmp=True)


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
	# "crash" the first dpservice and send reply to the other one
	dp_service_b.become_active()
	reply_pkt = (Ether(dst=pkt[Ether].src, src=pkt[Ether].dst) /
				 IPv6(dst=pkt[IPv6].src, src=pkt[IPv6].dst) /
				 UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport))
	delayed_sendp(reply_pkt, PF0.tap_b)

def test_ha_virtsvc(request, prepare_ifaces, prepare_ifaces_b, dp_service_b):
	if not request.config.getoption("--virtsvc"):
		pytest.skip("Virtual services not enabled")

	threading.Thread(target=virtsvc_responder, args=(dp_service_b,)).start()

	pkt = (Ether(dst=VM1.mac, src=VM1.mac) /
		   IP(dst=virtsvc_udp_virtual_ip, src=VM1.ip) /
		   UDP(dport=virtsvc_udp_virtual_port, sport=1234))
	delayed_sendp(pkt, VM1.tap)

	# Sniff the other dpservice
	reply = sniff_packet(VM1.tap_b, is_udp_pkt)
	assert reply[IP].src == virtsvc_udp_virtual_ip, \
		"Got answer from wrong UDP source ip"
	assert reply[UDP].sport == virtsvc_udp_virtual_port, \
		"Got answer from wrong UDP source port"
	assert reply[UDP].dport == 1234, \
		"Got answer to wrong UDP destination port"


#
# Packet-relay traffic (packet for neighboring NAT dpservice)
# should work because there is nothing extra to keep track of
# it is driven directly by LB/VNF tables which are kept the same by metalnet
#
def neighnat_sender(nat_ul, pf_tap):
	pkt = (Ether(dst=PF0.mac, src=PF0.mac) /
		   IPv6(dst=nat_ul, src=router_ul_ipv6) /
		   IP(dst=nat_vip, src=public_ip) /
		   UDP(dport=nat_neigh_min_port))
	delayed_sendp(pkt, pf_tap)

def neighnat_communicate(nat_ul, pf_tap):
	threading.Thread(target=neighnat_sender, args=(nat_ul, pf_tap)).start()
	# PF receives both the incoming packet and the relayed one, skip the first
	pkt = sniff_packet(pf_tap, is_udp_pkt, skip=1)
	assert pkt[IPv6].dst == neigh_vni1_ul_ipv6 and pkt[UDP].dport == nat_neigh_min_port, \
		f"Relayed packet not to the right neighbor destination"

def test_ha_packet_relay(prepare_ifaces, prepare_ifaces_b, grpc_client, grpc_client_b, dp_service_b):
	# The NAT address needs to be the same for both dpservices -> needs metalnet-generated underlays
	nat_ul = "fc00:1::8000:1234:1"
	grpc_client.addnat(VM1.name, nat_vip, nat_local_min_port, nat_local_max_port, preferred_underlay=nat_ul)
	grpc_client_b.addnat(VM1.name, nat_vip, nat_local_min_port, nat_local_max_port, preferred_underlay=nat_ul)
	grpc_client.addneighnat(nat_vip, vni1, nat_neigh_min_port, nat_neigh_max_port, neigh_vni1_ul_ipv6)
	grpc_client_b.addneighnat(nat_vip, vni1, nat_neigh_min_port, nat_neigh_max_port, neigh_vni1_ul_ipv6)

	neighnat_communicate(nat_ul, PF0.tap)

	# "crash" the first dpservice and repeat the test on the other once
	dp_service_b.become_active()

	neighnat_communicate(nat_ul, PF0.tap_b)

	grpc_client_b.delneighnat(nat_vip, vni1, nat_neigh_min_port, nat_neigh_max_port)
	grpc_client.delneighnat(nat_vip, vni1, nat_neigh_min_port, nat_neigh_max_port)
	grpc_client_b.delnat(VM1.name)
	grpc_client.delnat(VM1.name)


#
# Test requesting multiple NAT etries after the secondary dpservice restarts
#
def create_nat_entry(vm_tap, sport, dst_ip):
	# this is just sending packets out to create entries, no threads, no delay, no sniffing
	pkt = Ether(dst=PF0.mac, src=VM1.mac) / IP(dst=dst_ip, src=VM1.ip) / UDP(dport=1234, sport=sport)
	sendp(pkt, iface=vm_tap)

def create_nat_entry6(vm_tap, sport, dst_ip):
	# this is just sending packets out to create entries, no threads, no delay, no sniffing
	pkt = Ether(dst=PF0.mac, src=VM1.mac) / IPv6(dst=dst_ip, src=VM1.ipv6) / UDP(dport=1234, sport=sport)
	sendp(pkt, iface=vm_tap)

def bulk_responder(nat_ul, nat_port, dst_ip):
	reply_pkt = (Ether(dst=PF0.mac, src=PF0.mac) /
				 IPv6(dst=nat_ul, src=router_ul_ipv6) /
				 IP(dst=nat_vip, src=dst_ip) /
				 UDP(sport=1234, dport=nat_port))
	delayed_sendp(reply_pkt, PF0.tap_b)

def verify_bulk_sync(nat_ul, external_src_ip, nat_port, vm_port, ipv6=False):
	threading.Thread(target=bulk_responder, args=(nat_ul, nat_port, external_src_ip)).start()
	reply = sniff_packet(VM1.tap_b, is_udp_pkt)
	result = (reply[IPv6].dst == VM1.ipv6) if ipv6 else (reply[IP].dst == VM1.ip)
	assert result, \
		"Reply not to the right address"
	assert reply[UDP].dport == vm_port, \
		"Reply not to the right port"

def bulk_virtsvc_responder():
	# Hardcoded virtsvc IP and port, obtained by looking at --graphtrace output
	reply_pkt = (Ether(dst=PF0.mac, src=PF0.mac) /
				 IPv6(dst="fc00:1:0:0:0:4000:0:0", src=virtsvc_udp_svc_ipv6) /
				 UDP(dport=1025, sport=virtsvc_udp_svc_port))
	delayed_sendp(reply_pkt, PF0.tap_b)

def verify_virtsvc_bulk_sync():
	threading.Thread(target=bulk_virtsvc_responder).start()
	reply = sniff_packet(VM1.tap_b, is_udp_pkt)
	assert reply[IP].src == virtsvc_udp_virtual_ip, \
		"Got answer from wrong UDP source ip"
	assert reply[UDP].sport == virtsvc_udp_virtual_port, \
		"Got answer from wrong UDP source port"
	assert reply[UDP].dport == 1234, \
		"Got answer to wrong UDP destination port"

def test_ha_bulk(request, prepare_ifaces, grpc_client, grpc_client_b):
	# Need to create many entries with overloading to properly test table dump
	nat_port_range = 4
	nat_port_from = nat_local_min_port
	nat_port_to = nat_local_min_port + nat_port_range

	grpc_client.addnat(VM1.name, nat_vip, nat_port_from, nat_port_to)

	# Fill up NAT tables first
	for sport in range(1024, 1024+nat_port_range):
		create_nat_entry(VM1.tap, sport, public_ip2)  # Cannot use public_ip as that is already used by the NAT64 address
		create_nat_entry6(VM1.tap, sport, public_nat64_ipv6)

	if request.config.getoption("--virtsvc"):
		pkt = (Ether(dst=VM1.mac, src=VM1.mac) /
			   IP(dst=virtsvc_udp_virtual_ip, src=VM1.ip) /
			   UDP(dport=virtsvc_udp_virtual_port, sport=1234))
		sendp(pkt, iface=VM1.tap)

	# Only now start the second dpservice, it should request a NAT table dump
	dp_service_b = request.getfixturevalue('dp_service_b')
	request.getfixturevalue('prepare_ifaces_b')
	nat_ul_b = grpc_client_b.addnat(VM1.name, nat_vip, nat_port_from, nat_port_to)
	# give backup dpservice time to actually receive the table dump before switching to it
	time.sleep(0.5)
	dp_service_b.become_active()

	# Test some packets from outside to second dpservice
	# NOTE: the port values are hardcoded and were obtained by looking at --graphtrace output
	verify_bulk_sync(nat_ul_b, public_ip2, 102, 1025)
	verify_bulk_sync(nat_ul_b, public_ip, 100, 1026, ipv6=True)
	if request.config.getoption("--virtsvc"):
		verify_virtsvc_bulk_sync()

	grpc_client_b.delnat(VM1.name)
	grpc_client.delnat(VM1.name)
