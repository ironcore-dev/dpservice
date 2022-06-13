from scapy.all import *
from scapy.layers.l2 import Ether
from scapy.layers.inet6 import IPv6
from scapy.layers.dhcp6 import *
from scapy.contrib.geneve import GENEVE
from scapy.config import conf

import pytest, shlex, subprocess, time
from config import *
import multiprocessing


def test_nd(add_machine):
	answer = neighsol(gw_ip6, vf0_ipv6, iface=vf0_tap, timeout=2)
	mac = str(answer[ICMPv6NDOptDstLLAddr].lladdr)
	print(mac)
	assert(mac == vf0_mac)

def test_dhcp6(capsys):
	eth = Ether(dst=mc_mac)
	ip6 = IPv6(dst=gw_ip6)
	udp = UDP(sport=546,dport=547)
	sol = DHCP6_Solicit()
	req = DHCP6_Request()

	sol.trid = random.randint(0,16777215)
	rc_op = DHCP6OptRapidCommit(optlen=0)
	opreq = DHCP6OptOptReq()
	et_op= DHCP6OptElapsedTime()
	cid_op = DHCP6OptClientId()
	iana_op = DHCP6OptIA_NA(iaid=0x18702501)

	iana_op.optlen = 12
	iana_op.T1 = 0
	iana_op.T2 = 0
	cid_op.optlen = 28
	cid_op.duid = "00020000ab11b7d4e0eed266171d"
	opreq.optlen = 4

	pkt = eth/ip6/udp/sol/iana_op/rc_op/et_op/cid_op/opreq
	answer = srp1(pkt, iface=vf0_tap, type=ETH_P_IPV6, timeout=2)
	print(str(answer[DHCP6OptIAAddress].addr))
	pytest.assume(str(cid_op.duid) == str(answer[DHCP6OptClientId].duid))

	iana_op = answer[DHCP6OptIAAddress]
	pkt = eth/ip6/udp/req/iana_op/rc_op/et_op/cid_op/opreq
	answer = srp1(pkt, iface=vf0_tap, type=ETH_P_IPV6, timeout=2)
	pytest.assume(str(cid_op.duid) == str(answer[DHCP6OptClientId].duid))
	print(str(answer[DHCP6OptIAAddress].addr))
	assert(str(answer[DHCP6OptIAAddress].addr) == vf0_ipv6)


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

@pytest.mark.skipif(port_redundancy == True, reason = "port reduncy not support in ipv6 path")
def test_IPv6inIPv6(capsys, tun_opt):
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



