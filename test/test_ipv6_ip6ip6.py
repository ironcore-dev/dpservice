from scapy.all import *
from scapy.layers.l2 import Ether
from scapy.layers.inet6 import IPv6
from scapy.contrib.geneve import GENEVE

import pytest, time
from config import *
import multiprocessing


def is_geneve_encaped_icmpv6_pkt(pkt):
	if IPv6 in pkt:
		pktipv6=pkt[IPv6]
		if pktipv6.dst==ul_actual_dst and pktipv6.nh==17:
			return True
	return False

def is_encaped_icmpv6_pkt(pkt):
	if IPv6 in pkt:
		pktipv6=pkt[IPv6]
		if pktipv6.dst==ul_actual_dst and pktipv6.nh==0x29:
			return True
	return False

def is_icmpv6echo_pkt(pkt):
	if ICMPv6EchoReply in pkt:
		return True
	return False

def geneve_in_ipv6_responder():
	pkt_list = sniff(count=1,lfilter=is_geneve_encaped_icmpv6_pkt,iface=pf0_tap)
	pkt=pkt_list[0]

	pktether=pkt.getlayer(Ether)
	pktipv6 = pkt.getlayer(IPv6,1)
	pktip= pkt.getlayer(IPv6,2)

	reply_pkt = Ether(dst=pktether.src, src=pktether.dst, type=0x86DD)/IPv6(dst=ul_actual_src, src=pktipv6.dst, nh=17) / UDP(sport=6081, dport=6081) \
				/ GENEVE(vni=0x640000, proto=0x86DD) / IPv6(dst=pktip.src, src=pktip.dst, nh=58)/ICMPv6EchoReply(type=129)
	time.sleep(1)
	sendp(reply_pkt, iface=pf0_tap)

def ipv6_in_ipv6_responder():
	pkt_list = sniff(count=1,lfilter=is_encaped_icmpv6_pkt,iface=pf0_tap)
	pkt=pkt_list[0]

	pktether=pkt.getlayer(Ether)
	pktipv6 = pkt.getlayer(IPv6,1)
	pktip= pkt.getlayer(IPv6,2)

	reply_pkt = Ether(dst=pktether.src, src=pktether.dst, type=0x86DD)/IPv6(dst=ul_actual_src, src=pktipv6.dst, nh=0x29)/IPv6(dst=pktip.src, src=pktip.dst, nh=58)/ICMPv6EchoReply(type=129)
	time.sleep(1)
	sendp(reply_pkt, iface=pf0_tap)

def test_IPv6inIPv6(add_machine, tun_opt, port_redundancy):
	if port_redundancy:
		pytest.skip("port redundancy not supported in ipv6 path")

	d = None
	if tun_opt == tun_type_geneve:
		d = multiprocessing.Process(name="sniffer",target = geneve_in_ipv6_responder)
	else:
		d = multiprocessing.Process(name="sniffer",target = ipv6_in_ipv6_responder)

	d.daemon=False
	d.start()

	time.sleep(1)

	icmp_echo_pkt = Ether(dst=pf0_mac,src=vf0_mac,type=0x86DD)/IPv6(dst="2002::123",src="2001::10",nh=58)/ICMPv6EchoRequest()
	sendp(icmp_echo_pkt,iface=vf0_tap)
	
	pkt_list = sniff(count=1,lfilter=is_icmpv6echo_pkt,iface=vf0_tap,timeout=2)
	if len(pkt_list)==0:
		raise AssertionError('Cannot receive icmp reply!')
