import pytest
import shlex
import subprocess
import threading

from helpers import *


def geneve4_in_ipv6_icmp_responder(pf_name):
	pkt = sniff_packet(pf_name, is_geneve_encaped_icmp_pkt)
	reply_pkt = (Ether(dst=pkt[Ether].src, src=pkt[Ether].dst, type=0x86DD) /
				 IPv6(dst=router_ul_ipv6, src=pkt[IPv6].dst, nh=17) /
				 UDP(sport=6081, dport=6081) /
				 GENEVE(vni=geneve_vni1, proto=0x0800) /
				 IP(dst=pkt[IP].src, src=pkt[IP].dst) /
				 ICMP(type=0))
	delayed_sendp(reply_pkt, pf_name)

def ipv4_in_ipv6_icmp_responder(pf_name, vm_ipv6):
	pkt = sniff_packet(pf_name, is_encaped_icmp_pkt)
	# TODO assert proper tunnel here! (i.e. move filter here)
	reply_pkt = (Ether(dst=pkt[Ether].src, src=pkt[Ether].dst, type=0x86DD) /
				 IPv6(dst=vm_ipv6, src=pkt[IPv6].dst, nh=4) /
				 IP(dst=pkt[IP].src, src=pkt[IP].dst) /
				 ICMP(type=0))
	delayed_sendp(reply_pkt, pf_name)

def send_ipv4_icmp(dst_ip, pf_name, responder, vm_ipv6):
	threading.Thread(target=responder, args=(pf_name, vm_ipv6)).start()
	icmp_echo_pkt = (Ether(dst=pf0_mac, src=vf0_mac, type=0x0800) /
					 IP(dst=dst_ip, src=vf0_ip) /
					 ICMP(type=8))
	delayed_sendp(icmp_echo_pkt, vf0_tap)
	pkt = sniff_packet(vf0_tap, is_icmp_pkt)
	assert pkt[ICMP].type == 0, \
		"Wrong ICMP reply"

def test_ipv4_in_ipv6(prepare_ipv4, tun_opt, port_redundancy, dp_service):
	responder = geneve4_in_ipv6_icmp_responder if tun_opt == tun_type_geneve else ipv4_in_ipv6_icmp_responder
	send_ipv4_icmp(f"{neigh_vni1_ov_ip_prefix}.5", pf0_tap, responder, dp_service.vm1_ipv6)
	if port_redundancy:
		send_ipv4_icmp(f"{neigh_vni1_ov_ip_prefix}.8", pf1_tap, responder, dp_service.vm1_ipv6)


def geneve6_in_ipv6_icmp6_responder(pf_name):
	pkt = sniff_packet(pf_name, is_geneve_encaped_icmpv6_pkt)
	reply_pkt = (Ether(dst=pkt.getlayer(Ether).src, src=pkt.getlayer(Ether).dst, type=0x86DD) /
				 IPv6(dst=router_ul_ipv6, src=pkt.getlayer(IPv6,1).dst, nh=17) /
				 UDP(sport=6081, dport=6081) /
				 GENEVE(vni=geneve_vni1, proto=0x86DD) /
				 IPv6(dst=pkt.getlayer(IPv6,2).src, src=pkt.getlayer(IPv6,2).dst, nh=58) /
				 ICMPv6EchoReply(type=129))
	delayed_sendp(reply_pkt, pf_name)

def ipv6_in_ipv6_icmp6_responder(pf_name, vm1_ipv6):
	pkt = sniff_packet(pf_name, is_encaped_icmpv6_pkt)
	reply_pkt = (Ether(dst=pkt.getlayer(Ether).src, src=pkt.getlayer(Ether).dst, type=0x86DD) /
				 IPv6(dst=vm1_ipv6, src=pkt.getlayer(IPv6,1).dst, nh=0x29) /
				 IPv6(dst=pkt.getlayer(IPv6,2).src, src=pkt.getlayer(IPv6,2).dst, nh=58) /
				 ICMPv6EchoReply(type=129))
	delayed_sendp(reply_pkt, pf_name)

def test_ipv6_in_ipv6(prepare_ifaces, tun_opt, port_redundancy, dp_service):

	if port_redundancy:
		pytest.skip("Port redundancy is not supported for ipv6 in ipv6")

	responder = geneve6_in_ipv6_icmp6_responder if tun_opt == tun_type_geneve else ipv6_in_ipv6_icmp6_responder
	threading.Thread(target=responder, args=(pf0_tap, dp_service.vm1_ipv6)).start()

	icmp_echo_pkt = (Ether(dst=pf0_mac, src=vf0_mac, type=0x86DD) /
					 IPv6(dst=f"{neigh_vni1_ov_ipv6_prefix}::123", src=vf0_ipv6, nh=58) /
					 ICMPv6EchoRequest())
	delayed_sendp(icmp_echo_pkt, vf0_tap)

	pkt = sniff_packet(vf0_tap, is_icmpv6echo_pkt)
	assert pkt[ICMPv6EchoReply].type == 129, \
		"Bad ECHOv6 reply"
