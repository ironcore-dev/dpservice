from scapy.all import *
from scapy.layers.l2 import ARP
from scapy.layers.inet import Ether
from scapy.layers.dhcp import *
from scapy.config import conf

import pytest, shlex, subprocess, time
from config import *

import multiprocessing
import signal

def test_l2_arp(add_machine):
	try:
		arp_packet = Ether(dst=bcast_mac)/ARP(pdst=gw_ip4, hwdst=vf0_mac, psrc=null_ip)
		answer, unanswered = srp(arp_packet, iface=vf0_tap, type=ETH_P_ARP, timeout=2)

		for sent, received in answer:
			assert (str(received[ARP].hwsrc) == vf0_mac)
		time.sleep(1)
	except Exception as e:
		prepare_env.terminate()


def test_dhcpv4_vf0(capsys,add_machine):
	conf.checkIPaddr = False
	answer = dhcp_request(iface=vf0_tap, timeout=5)
	resp = str(answer[DHCP].options[0][1])
	print(str(resp))
	pytest.assume(str(resp) == str(2))
	dst_mac = answer[Ether].src
	dst_ip = answer[IP].src
	answer = srp1(Ether(dst=dst_mac) / IP(src=vf0_ip, dst=dst_ip) / UDP(sport=68, dport=67) /
				BOOTP(chaddr=vf0_mac) / DHCP(options=[("message-type", "request"), "end"]), iface=vf0_tap)
	print(str(answer[BOOTP].yiaddr))
	assert (str(answer[BOOTP].yiaddr) == vf0_ip)

def test_dhcpv4_vf1(capsys,add_machine):
	conf.checkIPaddr = False
	answer = dhcp_request(iface=vf1_tap, timeout=5)
	resp = str(answer[DHCP].options[0][1])
	print(str(resp))
	pytest.assume(str(resp) == str(2))
	dst_mac = answer[Ether].src
	dst_ip = answer[IP].src
	answer = srp1(Ether(dst=dst_mac) / IP(src=vf1_ip, dst=dst_ip) / UDP(sport=68, dport=67) /
				BOOTP(chaddr=vf0_mac) / DHCP(options=[("message-type", "request"), "end"]), iface=vf1_tap)
	print(str(answer[BOOTP].yiaddr))
	assert (str(answer[BOOTP].yiaddr) == vf1_ip)

def is_encaped_icmp_pkt(pkt):
	if IPv6 in pkt:
		pktipv6=pkt[IPv6]
		if pktipv6.dst==ul_actual_dst and pktipv6.nh==4:
			if ICMP in pkt:
				return True
	return False

def is_icmp_pkt(pkt):
	if ICMP in pkt:
		return True
	return False

def is_tcp_pkt(pkt):
	if TCP in pkt:
		return True
	return False

def ipv4_in_ipv6_responder():
	pkt_list = sniff(count=1,lfilter=is_encaped_icmp_pkt,iface=pf0_tap)
	pkt=pkt_list[0]
	pkt.show()
	if Ether in pkt:
		pktether=pkt[Ether]
	if IPv6 in pkt:
		pktipv6 = pkt[IPv6]
	if IP in pkt:
		pktip= pkt[IP]

	reply_pkt = Ether(dst=pktether.src,src=pktether.dst,type=0x86DD)/IPv6(dst=ul_actual_src,src=ul_target_ipv6,nh=4)/IP(dst=pktip.src,src=pktip.dst)/ICMP(type=0)
	time.sleep(1)
	sendp(reply_pkt, iface=pf0_tap)


def test_IPv4inIPv6(capsys,add_machine):
	d=multiprocessing.Process(name="sniffer",target=ipv4_in_ipv6_responder)
	d.daemon=False
	d.start()

	time.sleep(1)

	icmp_echo_pkt = Ether(dst=pf0_mac,src=vf0_mac,type=0x0800)/IP(dst="192.168.129.5",src="172.32.10.5")/ICMP(type=8)
	sendp(icmp_echo_pkt,iface=vf0_tap)
	
	pkt_list = sniff(count=1,lfilter=is_icmp_pkt,iface=vf0_tap,timeout=2)
	if len(pkt_list)==0:
		raise AssertionError('Cannot receive icmp reply!')
	

def vf_to_vf_tcp_responder():
	pkt_list = sniff(count=1,lfilter=is_tcp_pkt,iface=vf1_tap)
	pkt=pkt_list[0]
	pkt.show()
	if Ether in pkt:
		pktether=pkt[Ether]
	if IP in pkt:
		pktip= pkt[IP]

	reply_pkt = Ether(dst=pktether.src,src=pktether.dst,type=0x0800)/IP(dst=pktip.src,src=pktip.dst)/TCP()
	time.sleep(1)
	sendp(reply_pkt, iface=vf1_tap)


def test_vf_to_vf_tcp(capsys,add_machine):
	d=multiprocessing.Process(name="sniffer",target=vf_to_vf_tcp_responder)
	d.daemon=False
	d.start()

	time.sleep(1)

	tcp_pkt = Ether(dst=vf1_mac,src=vf0_mac,type=0x0800)/IP(dst=vf1_ip,src=vf0_ip)/TCP()
	sendp(tcp_pkt,iface=vf0_tap)
	
	pkt_list = sniff(count=1,lfilter=is_tcp_pkt,iface=vf0_tap,timeout=2)
	if len(pkt_list)==0:
		raise AssertionError('Cannot receive icmp reply!')