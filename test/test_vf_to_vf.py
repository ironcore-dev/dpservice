# SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
# SPDX-License-Identifier: Apache-2.0

import threading

import pytest
from helpers import *

def vf_to_vf_tcp_responder(vf_tap):
	pkt = sniff_packet(vf_tap, is_tcp_pkt)
	reply_pkt = (Ether(dst=pkt[Ether].src, src=pkt[Ether].dst, type=0x0800) /
				 IP(dst=pkt[IP].src, src=pkt[IP].dst) /
				 TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport))
	delayed_sendp(reply_pkt, vf_tap)

def test_vf_to_vf_tcp(prepare_ipv4, grpc_client):
	threading.Thread(target=vf_to_vf_tcp_responder, args=(VM2.tap,)).start()

	grpc_client.addfwallrule(VM2.name, "fw0-vm2", proto="tcp", dst_port_min=1234, dst_port_max=1234)
	tcp_pkt = (Ether(dst=VM2.mac, src=VM1.mac, type=0x0800) /
			   IP(dst=VM2.ip, src=VM1.ip) /
			   TCP(dport=1234))
	delayed_sendp(tcp_pkt, VM1.tap)

	sniff_packet(VM1.tap, is_tcp_pkt)
	grpc_client.delfwallrule(VM2.name, "fw0-vm2")


def test_vf_to_vf_vip_dnat(prepare_ipv4, grpc_client):
	threading.Thread(target=vf_to_vf_tcp_responder, args=(VM2.tap,)).start()

	grpc_client.addvip(VM2.name, vip_vip)
	grpc_client.addfwallrule(VM2.name, "fw0-vm2", proto="tcp", dst_port_min=1235, dst_port_max=1235)

	# vm1 (vf0) -> vm2 (vf2), vm2 has VIP, send packet to VIP from vm1 side, whether the packet is received
	# and sent back by vm2 (DNAT)
	tcp_pkt = (Ether(dst=VM2.mac, src=VM1.mac, type=0x0800) /
			   IP(dst=vip_vip, src=VM1.ip) /
			   TCP(sport=1200, dport=1235))
	delayed_sendp(tcp_pkt, VM1.tap)

	sniff_packet(VM1.tap, is_tcp_pkt)

	grpc_client.delvip(VM2.name)
	grpc_client.delfwallrule(VM2.name, "fw0-vm2")


def test1_vf_to_vf_firewall_tcp(prepare_ipv4, grpc_client):
	sniff_tcp_data = {}
	resp_thread = threading.Thread(target=sniff_tcp_fwall_packet, args=(VM2.tap, sniff_tcp_data))
	resp_thread.start()

	#Accept only tcp packets from the source ip VM1.ip / 32, do not care about the rest
	grpc_client.addfwallrule(VM2.name, "fw1-vm2", src_prefix=f"{VM1.ip}/32", proto="tcp")
	tcp_pkt = (Ether(dst=VM2.mac, src=VM1.mac, type=0x0800) /
			   IP(dst=VM2.ip, src=VM1.ip) /
			   TCP(sport=1001, dport=1234))
	delayed_sendp(tcp_pkt, VM1.tap)

	resp_thread.join()
	#It should arrive at the destination VM, as firewall allows it
	assert sniff_tcp_data["pkt"] != None
	grpc_client.delfwallrule(VM2.name, "fw1-vm2")

def test2_vf_to_vf_firewall_tcp(prepare_ipv4, grpc_client):
	pytest.skip("Skipping till firewall gets fully enabled")
	sniff_tcp_data = {}
	negated = True
	resp_thread = threading.Thread(target=sniff_tcp_fwall_packet, args=(VM2.tap, sniff_tcp_data, negated))
	resp_thread.start()

	#Accept only tcp packets from the source ip 1.2.3.4 / 16 range, do not care about the rest
	grpc_client.addfwallrule(VM2.name, "fw0-vm2", src_prefix="1.2.3.4/16", proto="tcp")
	tcp_pkt = (Ether(dst=VM2.mac, src=VM1.mac, type=0x0800) /
			   IP(dst=VM2.ip, src=VM1.ip) /
			   TCP(sport=1002, dport=1234))
	delayed_sendp(tcp_pkt, VM1.tap)

	resp_thread.join()
	#It should not arrive at the destination VM, as firewall filters it
	assert sniff_tcp_data["pkt"] == None
	grpc_client.delfwallrule(VM2.name, "fw0-vm2")


def vf_to_vf_icmp_responder(vf_tap):
	pkt = sniff_packet(vf_tap, is_icmp_pkt)
	reply_pkt = (Ether(dst=pkt[Ether].src, src=pkt[Ether].dst, type=0x0800) / IP(dst=pkt[IP].src, src=pkt[IP].dst) / ICMP(type=0, id=pkt[ICMP].id))
	delayed_sendp(reply_pkt, vf_tap)

	pkt = sniff_packet(vf_tap, is_icmp_pkt)
	delayed_sendp(reply_pkt, vf_tap)

# send icmp packet from vm1 to vm2, vm2 replies back, for twice
def test_vf_to_vf_icmp(prepare_ipv4, grpc_client):
	icmp_respond_thread = threading.Thread(target=vf_to_vf_icmp_responder, args=(VM2.tap,))
	icmp_pkt = (Ether(dst=VM2.mac, src=VM1.mac, type=0x0800) / IP(dst=VM2.ip, src=VM1.ip) / ICMP(type=8, id=0x0040))
	icmp_respond_thread.start()
	delayed_sendp(icmp_pkt, VM1.tap)
	sniff_packet(VM1.tap, is_icmp_pkt)

	delayed_sendp(icmp_pkt, VM1.tap)
	sniff_packet(VM1.tap, is_icmp_pkt)

def vf_to_vf_icmpv6_responder(vf_tap):
	pkt = sniff_packet(vf_tap, is_icmpv6_echo_pkt)
	reply_pkt = (Ether(dst=pkt[Ether].src, src=pkt[Ether].dst, type=0x86DD) / IPv6(dst=pkt[IPv6].src, src=pkt[IPv6].dst, nh=58) / ICMPv6EchoReply(type=129))
	delayed_sendp(reply_pkt, vf_tap)
	pkt = sniff_packet(vf_tap, is_icmpv6_echo_pkt)
	delayed_sendp(reply_pkt, vf_tap)

# send icmpv6 packet from vm1 to vm2, vm2 replies back, for twice
def test_vf_to_vf_icmpv6(prepare_ipv4, grpc_client):
	icmpv6_respond_thread = threading.Thread(target=vf_to_vf_icmpv6_responder, args=(VM2.tap,))
	icmpv6_pkt = (Ether(dst=VM2.mac, src=VM1.mac, type=0x86DD) / IPv6(dst=VM2.ipv6, src=VM1.ipv6, nh=58) / ICMPv6EchoRequest())
	icmpv6_respond_thread.start()
	delayed_sendp(icmpv6_pkt, VM1.tap)
	sniff_packet(VM1.tap, is_icmpv6echo_reply_pkt)

	delayed_sendp(icmpv6_pkt, VM1.tap)
	sniff_packet(VM1.tap, is_icmpv6echo_reply_pkt)

def vf_to_vf_ipv6_tcp_responder(vf_tap):
	pkt = sniff_packet(vf_tap, is_ipv6_tcp_pkt)
	reply_pkt = (Ether(dst=pkt[Ether].src, src=pkt[Ether].dst, type=0x86DD) /
				 IPv6(dst=pkt[IPv6].src, src=pkt[IPv6].dst) /
				 TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport))
	delayed_sendp(reply_pkt, vf_tap)


def test_vf_to_vf_ipv6_tcp(prepare_ipv4, grpc_client):

	threading.Thread(target=vf_to_vf_ipv6_tcp_responder, args=(VM2.tap,)).start()

	tcp_pkt = (Ether(dst=VM2.mac, src=VM1.mac, type=0x86DD) /
			   IPv6(dst=VM2.ipv6, src=VM1.ipv6) /
			   TCP(dport=1234))
	delayed_sendp(tcp_pkt, VM1.tap)

	sniff_packet(VM1.tap, is_ipv6_tcp_pkt)