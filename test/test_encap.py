import pytest
import shlex
import subprocess
import threading

from helpers import *


def ipv4_in_ipv6_icmp_responder(pf_name, vm_ipv6):
	pkt = sniff_packet(pf_name, is_encaped_icmp_pkt)
	assert pkt[IPv6].dst == neigh_vni1_ul_ipv6, \
		"Invalid destination in encaped request"
	reply_pkt = (Ether(dst=pkt[Ether].src, src=pkt[Ether].dst, type=0x86DD) /
				 IPv6(dst=vm_ipv6, src=pkt[IPv6].dst, nh=4) /
				 IP(dst=pkt[IP].src, src=pkt[IP].dst) /
				 ICMP(type=0))
	delayed_sendp(reply_pkt, pf_name)

def send_ipv4_icmp(dst_ip, pf_name, responder, vm_ipv6):
	threading.Thread(target=responder, args=(pf_name, vm_ipv6)).start()
	icmp_echo_pkt = (Ether(dst=PF0.mac, src=VM1.mac, type=0x0800) /
					 IP(dst=dst_ip, src=VM1.ip) /
					 ICMP(type=8))
	delayed_sendp(icmp_echo_pkt, VM1.tap)
	pkt = sniff_packet(VM1.tap, is_icmp_pkt)
	assert pkt[ICMP].type == 0, \
		"Wrong ICMP reply"

def test_ipv4_in_ipv6(prepare_ipv4, port_redundancy):
	send_ipv4_icmp(f"{neigh_vni1_ov_ip_prefix}.5", PF0.tap, ipv4_in_ipv6_icmp_responder, VM1.ul_ipv6)
	if port_redundancy:
		send_ipv4_icmp(f"{neigh_vni1_ov_ip_prefix}.8", PF1.tap, ipv4_in_ipv6_icmp_responder, VM1.ul_ipv6)


def ipv6_in_ipv6_icmp6_responder(pf_name, vm_ul_ipv6):
	pkt = sniff_packet(pf_name, is_encaped_icmpv6_pkt)
	assert pkt[IPv6].dst == neigh_vni1_ul_ipv6, \
		"Invalid destination in encaped request"
	reply_pkt = (Ether(dst=pkt.getlayer(Ether).src, src=pkt.getlayer(Ether).dst, type=0x86DD) /
				 IPv6(dst=vm_ul_ipv6, src=pkt.getlayer(IPv6,1).dst, nh=0x29) /
				 IPv6(dst=pkt.getlayer(IPv6,2).src, src=pkt.getlayer(IPv6,2).dst, nh=58) /
				 ICMPv6EchoReply(type=129))
	delayed_sendp(reply_pkt, pf_name)

def test_ipv6_in_ipv6(prepare_ifaces, port_redundancy):

	if port_redundancy:
		pytest.skip("Port redundancy is not supported for ipv6 in ipv6")

	threading.Thread(target=ipv6_in_ipv6_icmp6_responder, args=(PF0.tap, VM1.ul_ipv6)).start()

	icmp_echo_pkt = (Ether(dst=PF0.mac, src=VM1.mac, type=0x86DD) /
					 IPv6(dst=f"{neigh_vni1_ov_ipv6_prefix}::123", src=VM1.ipv6, nh=58) /
					 ICMPv6EchoRequest())
	delayed_sendp(icmp_echo_pkt, VM1.tap)

	pkt = sniff_packet(VM1.tap, is_icmpv6echo_pkt)
	assert pkt[ICMPv6EchoReply].type == 129, \
		"Bad ECHOv6 reply"
