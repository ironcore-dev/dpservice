import pytest
import shlex
import subprocess
import threading

from helpers import *


def geneve4_in_ipv6_icmp_responder(pf_name):
	pkt = sniff(count=1, lfilter=is_geneve_encaped_icmp_pkt, iface=pf_name, timeout=2)[0]
	reply_pkt = (Ether(dst=pkt[Ether].src, src=pkt[Ether].dst, type=0x86DD) /
				 IPv6(dst=ul_actual_src, src=pkt[IPv6].dst, nh=17) /
				 UDP(sport=6081, dport=6081) /
				 GENEVE(vni=0x640000, proto=0x0800) /
				 IP(dst=pkt[IP].src, src=pkt[IP].dst) /
				 ICMP(type=0))
	delayed_sendp(reply_pkt, pf_name)

def ipv4_in_ipv6_icmp_responder(pf_name, vm1_ipv6):
	pkt = sniff(count=1, lfilter=is_encaped_icmp_pkt, iface=pf_name, timeout=2)[0]
	reply_pkt = (Ether(dst=pkt[Ether].src, src=pkt[Ether].dst, type=0x86DD) /
				 IPv6(dst=vm1_ipv6, src=pkt[IPv6].dst, nh=4) /
				 IP(dst=pkt[IP].src, src=pkt[IP].dst) /
				 ICMP(type=0))
	delayed_sendp(reply_pkt, pf_name)

def test_ipv4_in_ipv6(prepare_ipv4, tun_opt, port_redundancy):

	responder = geneve4_in_ipv6_icmp_responder if tun_opt == tun_type_geneve else ipv4_in_ipv6_icmp_responder
	vm1_ipv6 = prepare_ipv4
	threading.Thread(target=responder, args=(pf0_tap, vm1_ipv6)).start()
	if port_redundancy:
		threading.Thread(target=responder, args=(pf1_tap,)).start()

	icmp_echo_pkt = (Ether(dst=pf0_mac, src=vf0_mac, type=0x0800) /
					 IP(dst="192.168.129.5", src="172.32.10.5") /
					 ICMP(type=8))
	delayed_sendp(icmp_echo_pkt, vf0_tap)
	pkt_list = sniff(count=1, lfilter=is_icmp_pkt, iface=vf0_tap, timeout=2)
	assert len(pkt_list) == 1, \
		"No ECHO reply"

	if port_redundancy:
		icmp_echo_pkt = (Ether(dst=pf0_mac, src=vf0_mac, type=0x0800) /
						 IP(dst="192.168.129.6", src="172.32.10.5") /
						 ICMP(type=8))
		delayed_sendp(icmp_echo_pkt, vf0_tap)
		pkt_list = sniff(count=1, lfilter=is_icmp_pkt, iface=vf0_tap, timeout=2)
		assert len(pkt_list) == 1, \
			"No ECHO reply on second PF"


def geneve6_in_ipv6_icmp6_responder(pf_name):
	pkt = sniff(count=1, lfilter=is_geneve_encaped_icmpv6_pkt, iface=pf_name, timeout=2)[0]
	reply_pkt = (Ether(dst= pkt.getlayer(Ether).src, src= pkt.getlayer(Ether).dst, type=0x86DD) /
				 IPv6(dst=ul_actual_src, src=pkt.getlayer(IPv6,1).dst, nh=17) /
				 UDP(sport=6081, dport=6081) /
				 GENEVE(vni=0x640000, proto=0x86DD) /
				 IPv6(dst=pkt.getlayer(IPv6,2).src, src=pkt.getlayer(IPv6,2).dst, nh=58) /
				 ICMPv6EchoReply(type=129))
	delayed_sendp(reply_pkt, pf_name)

def ipv6_in_ipv6_icmp6_responder(pf_name, vm1_ipv6):
	pkt = sniff(count=1, lfilter=is_encaped_icmpv6_pkt, iface=pf_name, timeout=2)[0]
	reply_pkt = (Ether(dst=pkt.getlayer(Ether).src, src=pkt.getlayer(Ether).dst, type=0x86DD) /
				 IPv6(dst=vm1_ipv6, src=pkt.getlayer(IPv6,1).dst, nh=0x29) /
				 IPv6(dst=pkt.getlayer(IPv6,2).src, src=pkt.getlayer(IPv6,2).dst, nh=58) /
				 ICMPv6EchoReply(type=129))
	delayed_sendp(reply_pkt, pf_name)

def test_ipv6_in_ipv6(prepare_ifaces, tun_opt, port_redundancy):

	if port_redundancy:
		pytest.skip("Port redundancy is not supported for ipv6 in ipv6")

	vm1_ipv6 = prepare_ifaces
	responder = geneve6_in_ipv6_icmp6_responder if tun_opt == tun_type_geneve else ipv6_in_ipv6_icmp6_responder
	threading.Thread(target=responder, args=(pf0_tap, vm1_ipv6)).start()

	icmp_echo_pkt = (Ether(dst=pf0_mac, src=vf0_mac, type=0x86DD) /
					 IPv6(dst="2002::123", src="2001::10", nh=58) /
					 ICMPv6EchoRequest())
	delayed_sendp(icmp_echo_pkt, vf0_tap)

	pkt_list = sniff(count=1, lfilter=is_icmpv6echo_pkt, iface=vf0_tap, timeout=2)
	assert len(pkt_list) == 1, \
		"No ECHOv6 reply"
