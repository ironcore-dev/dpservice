# SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
# SPDX-License-Identifier: Apache-2.0

import pytest
import threading

from helpers import *

def reply_icmp_pkt_from_vm1(nat_ul_ipv6):
	pkt = sniff_packet(PF0.tap, is_icmp_pkt)
	src_ip = pkt[IP].src
	assert src_ip == nat_vip, \
		f"Bad ICMP request (src ip: {src_ip})"

	reply_pkt = (Ether(dst=pkt[Ether].src, src=pkt[Ether].dst, type=0x86DD) /
				 IPv6(dst=nat_ul_ipv6, src=pkt[IPv6].dst, nh=4) /
				 IP(dst=pkt[IP].src, src=pkt[IP].dst) /
				 ICMP(type=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq))
	delayed_sendp(reply_pkt, PF0.tap)

def test_vf_to_pf_network_nat_icmp(prepare_ipv4, grpc_client):
	nat_ul_ipv6 = grpc_client.addnat(VM1.name, nat_vip, nat_local_min_port, nat_local_max_port)

	threading.Thread(target=reply_icmp_pkt_from_vm1, args=(nat_ul_ipv6,)).start()

	icmp_pkt = (Ether(dst=PF0.mac, src=VM1.mac, type=0x0800) /
			    IP(dst=public_ip3, src=VM1.ip) /
			    ICMP(type=8, id=0x0040))
	delayed_sendp(icmp_pkt, VM1.tap)

	pkt = sniff_packet(VM1.tap, is_icmp_pkt)
	dst_ip = pkt[IP].dst
	assert dst_ip == VM1.ip, \
		f"Bad ECHO reply (dst ip: {dst_ip})"

	grpc_client.delnat(VM1.name)

def test_vf_to_pf_network_nat_icmpv6(prepare_ipv4, grpc_client):
	nat_ul_ipv6 = grpc_client.addnat(VM1.name, nat_vip, nat_local_min_port, nat_local_max_port)

	threading.Thread(target=reply_icmp_pkt_from_vm1, args=(nat_ul_ipv6,)).start()

	icmp_pkt = (Ether(dst=PF0.mac, src=VM1.mac, type=0x86DD) /
					 IPv6(dst=public_nat64_ipv6, src=VM1.ipv6, nh=58) /
					 ICMPv6EchoRequest(seq=1))

	delayed_sendp(icmp_pkt, VM1.tap)

	pkt = sniff_packet(VM1.tap, is_icmpv6echo_reply_pkt)
	dst_ip = pkt[IPv6].dst
	assert dst_ip == VM1.ipv6, \
		f"Bad ECHO reply (dst ip: {dst_ip})"

	grpc_client.delnat(VM1.name)


def reply_tcp_if_port_not(forbidden_port, nat_ul_ipv6):
	pkt = sniff_packet(PF0.tap, is_tcp_pkt)
	src_ip = pkt[IP].src
	sport = pkt[TCP].sport
	assert src_ip == nat_vip and sport >= nat_local_min_port and sport < nat_local_max_port, \
		f"Bad TCP packet (ip: {src_ip}, sport: {sport})"

	if forbidden_port is None or sport != forbidden_port:
		reply_pkt = (Ether(dst=pkt[Ether].src, src=pkt[Ether].dst, type=0x86DD) /
					 IPv6(dst=nat_ul_ipv6, src=pkt[IPv6].dst, nh=4) /
					 IP(dst=pkt[IP].src, src=pkt[IP].dst) /
					 TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport))
		delayed_sendp(reply_pkt, PF0.tap)

	return sport

def reply_tcp_pkt_from_vm1(nat_ul_ipv6):
	reply_tcp_if_port_not(None, nat_ul_ipv6)

def reply_tcp_pkt_from_vm1_max_port(nat_ul_ipv6):
	sport = reply_tcp_if_port_not(None, nat_ul_ipv6)
	reply_tcp_if_port_not(sport, nat_ul_ipv6)

def send_tcp_through_port(port):
	tcp_pkt = (Ether(dst=PF0.mac, src=VM1.mac, type=0x0800) /
			   IP(dst=public_ip3, src=VM1.ip) /
			   TCP(sport=port))
	delayed_sendp(tcp_pkt, VM1.tap)

	pkt = sniff_packet(VM1.tap, is_tcp_pkt)
	dst_ip = pkt[IP].dst
	dport = pkt[TCP].dport
	assert dst_ip == VM1.ip and dport == port, \
		f"Bad TCP packet (ip: {dst_ip}, dport: {dport})"

def send_tcp_through_port_with_ipv6(port):

	tcp_pkt = (Ether(dst=PF0.mac, src=VM1.mac, type=0x86DD) /
			   IPv6(dst=public_nat64_ipv6, src=VM1.ipv6) /
			   TCP(sport=port))
	delayed_sendp(tcp_pkt, VM1.tap)

	pkt = sniff_packet(VM1.tap, is_ipv6_tcp_pkt)
	dst_ip = pkt[IPv6].dst
	dport = pkt[TCP].dport
	assert dst_ip == VM1.ipv6 and dport == port, \
		f"Bad TCP packet (ip: {dst_ip}, dport: {dport})"


def test_vf_to_pf_network_nat_max_port_tcp(prepare_ipv4, grpc_client, port_redundancy):
	nat_ul_ipv6 = grpc_client.addnat(VM1.name, nat_vip, nat_local_min_port, nat_local_max_port)
	threading.Thread(target=reply_tcp_pkt_from_vm1_max_port, args=(nat_ul_ipv6,)).start()
	send_tcp_through_port(1246)
	send_tcp_through_port(1547)
	grpc_client.delnat(VM1.name)


def test_vf_to_pf_network_nat_tcp(prepare_ipv4, grpc_client):
	nat_ul_ipv6 = grpc_client.addnat(VM1.name, nat_vip, nat_local_min_port, nat_local_max_port)
	threading.Thread(target=reply_tcp_pkt_from_vm1, args=(nat_ul_ipv6,)).start()
	send_tcp_through_port(1246)
	grpc_client.delnat(VM1.name)

def test_vf_to_pf_network_nat_tcp_with_ipv6(prepare_ipv4, grpc_client):
	nat_ul_ipv6 = grpc_client.addnat(VM1.name, nat_vip, nat_local_min_port, nat_local_max_port)
	threading.Thread(target=reply_tcp_pkt_from_vm1, args=(nat_ul_ipv6,)).start()
	send_tcp_through_port_with_ipv6(1246)
	grpc_client.delnat(VM1.name)

def encaped_tcp_in_ipv6_vip_responder(pf_name, vip_ul_ipv6):
	pkt = sniff_packet(pf_name, is_tcp_pkt)
	reply_pkt = (Ether(dst=pkt[Ether].src, src=pkt[Ether].dst, type=0x86DD) /
				 IPv6(dst=vip_ul_ipv6, src=pkt[IPv6].dst, nh=4) /
				 IP(dst=pkt[IP].src, src=pkt[IP].dst) /
				 TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport))
	delayed_sendp(reply_pkt, pf_name)

def request_tcp(dport, pf_name, vip_ul_ipv6):
	threading.Thread(target=encaped_tcp_in_ipv6_vip_responder, args=(pf_name, vip_ul_ipv6)).start()
	# vm2 (vf1) -> PF0/PF1 (internet traffic), vm2 has VIP, check on PFs side, whether VIP is source (SNAT)
	tcp_pkt = (Ether(dst=PF0.mac, src=VM2.mac, type=0x0800) /
			   IP(dst=public_ip, src=VM2.ip) /
			   TCP(sport=1240, dport=dport))
	delayed_sendp(tcp_pkt, VM2.tap)
	sniff_packet(VM2.tap, is_tcp_pkt)

def test_vf_to_pf_vip_snat(prepare_ipv4, grpc_client, port_redundancy):
	vip_ul_ipv6 = grpc_client.addvip(VM2.name, vip_vip)
	request_tcp(180, PF0.tap, vip_ul_ipv6)
	if port_redundancy:
		request_tcp(120, PF1.tap, vip_ul_ipv6)
	grpc_client.delvip(VM2.name)


def reply_with_icmp_err_fragment_needed(pf_name, nat_ul_ipv6):
	pkt = sniff_packet(pf_name, is_tcp_pkt)
	orig_ip_pkt = pkt[IP]
	reply_pkt = (Ether(dst=pkt[Ether].src, src=pkt[Ether].dst, type=0x86DD) /
				 IPv6(dst=nat_ul_ipv6, src=pkt[IPv6].dst, nh=4) /
				 IP(dst=orig_ip_pkt.src, src=orig_ip_pkt.dst) /
				 ICMP(type=3, code=4, unused=1280) /
				 orig_ip_pkt)
	# https://blog.cloudflare.com/path-mtu-discovery-in-practice/
	"""
	reply_pkt = (Ether(dst=pkt[Ether].src, src=pkt[Ether].dst, type=0x86DD) /
				 IPv6(dst=nat_ul_ipv6, src=pkt[IPv6].dst, nh=4) /
				 IP(dst=orig_ip_pkt.src, src=orig_ip_pkt.dst) /
				 ICMP(type=3, code=4, unused=1280) /
				 str(orig_ip_pkt)[:28])
	"""
	delayed_sendp(reply_pkt, pf_name)

def request_icmperr(dport, pf_name, nat_ul_ipv6):
	threading.Thread(target=reply_with_icmp_err_fragment_needed, args=(pf_name, nat_ul_ipv6)).start();

	tcp_pkt = (Ether(dst=ipv6_multicast_mac, src=VM1.mac, type=0x0800) /
			   IP(dst=public_ip, src=VM1.ip) /
			   TCP(sport=1256, dport=dport))
	delayed_sendp(tcp_pkt, VM1.tap)

	pkt = sniff_packet(VM1.tap, is_icmp_pkt)
	icmp_type = pkt[ICMP].type
	assert icmp_type == 3, \
		f"Received wrong icmp packet type: {icmp_type}"

def test_vm_nat_async_tcp_icmperr(prepare_ipv4, grpc_client, port_redundancy):
	nat_ul_ipv6 = grpc_client.addnat(VM1.name, nat_vip, nat_local_min_port, nat_local_max_port)
	request_icmperr(501, PF0.tap, nat_ul_ipv6)
	if port_redundancy:
		request_icmperr(565, PF1.tap, nat_ul_ipv6)
	grpc_client.delnat(VM1.name)

def test_vf_to_pf_firewall_tcp_block(prepare_ipv4, grpc_client):
	pytest.skip("Skipping till firewall gets fully enabled")
	sniff_tcp_data = {}
	negated = True
	resp_thread = threading.Thread(target=sniff_tcp_fwall_packet, args=(PF0.tap, sniff_tcp_data, negated))
	resp_thread.start()
	# Allow only tcp packets leaving the VM with destination port 453
	grpc_client.addfwallrule(VM1.name, "fw0-vm1", proto="tcp", dst_port_min=453, dst_port_max=453, direction="egress")
	tcp_pkt = (Ether(dst=PF0.mac, src=VM1.mac, type=0x0800) /
			   IP(dst=public_ip, src=VM1.ip) /
			   TCP(dport=1024))
	delayed_sendp(tcp_pkt, VM1.tap)

	resp_thread.join()
	assert sniff_tcp_data["pkt"] == None, \
		"Packet should have been filtered"
	grpc_client.delfwallrule(VM1.name, "fw0-vm1")

def test_vf_to_pf_firewall_tcp_allow(prepare_ipv4, grpc_client, port_redundancy):
	if port_redundancy:
		pytest.skip()
	sniff_tcp_data = {}
	resp_thread = threading.Thread(target=sniff_tcp_fwall_packet, args=(PF0.tap, sniff_tcp_data,))
	resp_thread.start()
	# Allow only tcp packets leaving the VM with destination port 453
	grpc_client.addfwallrule(VM1.name, "fw1-vm1", proto="tcp", dst_port_min=453, dst_port_max=453, direction="egress")
	tcp_pkt = (Ether(dst=PF0.mac, src=VM1.mac, type=0x0800) /
			   IP(dst=public_ip, src=VM1.ip) /
			   TCP(dport=453))
	delayed_sendp(tcp_pkt, VM1.tap)

	resp_thread.join()
	assert sniff_tcp_data["pkt"] != None, \
		"Packet should not have been filtered"
	grpc_client.delfwallrule(VM1.name, "fw1-vm1")

def encaped_tcp_ipv6_in_ipv6_responder(pf_name):
	pkt = sniff_packet(pf_name, is_ipv6_tcp_pkt)
	reply_pkt = (Ether(dst=pkt.getlayer(Ether).src, src=pkt.getlayer(Ether).dst, type=0x86DD) /
				 IPv6(dst=pkt.getlayer(IPv6,1).src, src=pkt.getlayer(IPv6,1).dst, nh=0x29) /
				 IPv6(dst=pkt.getlayer(IPv6,2).src, src=pkt.getlayer(IPv6,2).dst) /
				 TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport))
	delayed_sendp(reply_pkt, pf_name)

def test_vf_to_pf_tcp_in_ipv6(prepare_ipv4, grpc_client):
	threading.Thread(target=encaped_tcp_ipv6_in_ipv6_responder, args=(PF0.tap,)).start()
	# vm2 (vf1) -> PF0 (ipv6 internet traffic), PF0 replies back
	tcp_pkt = (Ether(dst=PF0.mac, src=VM2.mac, type=0x86DD) /
			   IPv6(dst=public_ipv6, src=VM2.ipv6) /
			   TCP(sport=1240, dport=180))
	delayed_sendp(tcp_pkt, VM2.tap)
	pkt = sniff_packet(VM2.tap, is_tcp_pkt)
	assert pkt[TCP].dport == 1240, \
		f"Received wrong dport in packet: {pkt[TCP].dport}"
