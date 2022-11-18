import time

from config import *
from helpers import *

def is_encaped_icmp_pkt(pkt):
	if IPv6 in pkt:
		pktipv6=pkt[IPv6]
		if pktipv6.dst==ul_actual_dst and pktipv6.nh==4:
			if ICMP in pkt:
				return True
	return False

def is_geneve_encaped_icmp_pkt(pkt):
	if IPv6 in pkt:
		pktipv6=pkt[IPv6]
		if pktipv6.dst==ul_actual_dst and pktipv6.nh==17:
			if ICMP in pkt:
				return True
	return False

def ipv4_in_ipv6_responder(pf_name):
	pkt_list = sniff(count=1,lfilter=is_encaped_icmp_pkt,iface=pf_name,timeout=10)

	if len(pkt_list)==0:
		return

	pkt=pkt_list[0]
	pkt.show()
	if Ether in pkt:
		pktether=pkt[Ether]
	if IPv6 in pkt:
		pktipv6 = pkt[IPv6]
	if IP in pkt:
		pktip= pkt[IP]

	reply_pkt = Ether(dst=pktether.src, src=pktether.dst, type=0x86DD)/IPv6(dst=ul_actual_src, src=pktipv6.dst, nh=4)/IP(dst=pktip.src, src=pktip.dst) / ICMP(type=0)
	time.sleep(1)
	sendp(reply_pkt, iface=pf_name)

def encaped_tcp_in_ipv6_vip_responder(pf_name):
	pkt_list = sniff(count=1,lfilter=is_tcp_pkt,iface=pf_name,timeout=10)

	if len(pkt_list)==0:
		return

	pkt=pkt_list[0]
	pkt.show()
	if Ether in pkt:
		pktether=pkt[Ether]
	if IPv6 in pkt:
		pktipv6 = pkt[IPv6]
	if IP in pkt:
		pktip= pkt[IP]
	if TCP in pkt:
		pkttcp = pkt[TCP]

	reply_pkt = Ether(dst=pktether.src, src=pktether.dst, type=0x86DD)/IPv6(dst=ul_actual_src, src=pktipv6.dst, nh=4)/IP(dst=pktip.src, src=pktip.dst) /TCP(sport=pkttcp.dport, dport=pkttcp.sport)
	time.sleep(1)
	sendp(reply_pkt, iface=pf_name)

def geneve_in_ipv6_responder(pf_name):
	pkt_list = sniff(count=1,lfilter=is_geneve_encaped_icmp_pkt, iface=pf_name,timeout=8)
	pkt=pkt_list[0]
	pkt.show()

	if Ether in pkt:
		pktether=pkt[Ether]
	if IPv6 in pkt:
		pktipv6 = pkt[IPv6]
	if IP in pkt:
		pktip = pkt[IP]

	reply_pkt = Ether(dst=pktether.src, src=pktether.dst, type=0x86DD)/IPv6(dst=ul_actual_src, src=pktipv6.dst, nh=17) / UDP(sport=6081, dport=6081) \
				/ GENEVE(vni=0x640000, proto=0x0800) / IP(dst=pktip.src, src=pktip.dst) / ICMP(type=0)
	time.sleep(1)
	sendp(reply_pkt, iface=pf_name)

def vf_to_vf_tcp_vf1_responder():
	pkt_list = sniff(count=1,lfilter=is_tcp_pkt,iface=vf1_tap)
	pkt=pkt_list[0]

	if Ether in pkt:
		pktether = pkt[Ether]
	if IP in pkt:
		pktip = pkt[IP]
	if TCP in pkt:
		pkttcp = pkt[TCP]

	reply_pkt = Ether(dst=pktether.src,src=pktether.dst,type=0x0800)/IP(dst=pktip.src,src=pktip.dst)/TCP(sport=pkttcp.dport, dport=pkttcp.sport)
	time.sleep(1)
	sendp(reply_pkt, iface=vf1_tap)

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
