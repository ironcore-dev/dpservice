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

	grpc_client.addfwallrule(VM2.name, "fw0-vm2", "0.0.0.0", 0, "0.0.0.0", 0, -1, -1, 1234, 1234, "tcp", "accept", "ingress")
	tcp_pkt = (Ether(dst=VM2.mac, src=VM1.mac, type=0x0800) /
			   IP(dst=VM2.ip, src=VM1.ip) /
			   TCP(dport=1234))
	delayed_sendp(tcp_pkt, VM1.tap)

	sniff_packet(VM1.tap, is_tcp_pkt)
	grpc_client.delfwallrule(VM2.name, "fw0-vm2")


def test_vf_to_vf_vip_dnat(prepare_ipv4, grpc_client):

	threading.Thread(target=vf_to_vf_tcp_responder, args=(VM2.tap,)).start()

	grpc_client.addvip(VM2.name, vip_vip)
	grpc_client.addfwallrule(VM2.name, "fw0-vm2", "0.0.0.0", 0, "0.0.0.0", 0, -1, -1, 1235, 1235, "tcp", "accept", "ingress")

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
	grpc_client.addfwallrule(VM2.name, "fw1-vm2", f"{VM1.ip}", 32, "0.0.0.0", 0, -1, -1, -1, -1, "tcp", "accept", "ingress")
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
	grpc_client.addfwallrule(VM2.name, "fw0-vm2", "1.2.3.4", 16, "0.0.0.0", 0, -1, -1, -1, -1, "tcp", "accept", "ingress")
	tcp_pkt = (Ether(dst=VM2.mac, src=VM1.mac, type=0x0800) /
			   IP(dst=VM2.ip, src=VM1.ip) /
			   TCP(sport=1002, dport=1234))
	delayed_sendp(tcp_pkt, VM1.tap)

	resp_thread.join()
	#It should not arrive at the destination VM, as firewall filters it
	assert sniff_tcp_data["pkt"] == None
	grpc_client.delfwallrule(VM2.name, "fw0-vm2")
