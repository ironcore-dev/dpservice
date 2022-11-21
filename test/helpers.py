import time

from scapy.all import *
from scapy.layers.dhcp import *
from scapy.layers.inet import Ether, ICMP, TCP
from scapy.layers.inet6 import IPv6
from scapy.contrib.geneve import GENEVE

from config import *


def request_ip(interface):
	scapy.config.conf.checkIPaddr = False
	answer = dhcp_request(iface=interface, timeout=5)
	resp = str(answer[DHCP].options[0][1])
	if resp != '2':
		raise AssertionError('Invalid DHCP response')


def is_icmp_pkt(pkt):
	return ICMP in pkt

def is_tcp_pkt(pkt):
	return TCP in pkt

def is_tcp_vip_src_pkt(pkt):
	return TCP in pkt and pkt[IP].src == virtual_ip

def is_icmpv6echo_pkt(pkt):
	return ICMPv6EchoReply in pkt

def is_geneve_encaped_icmpv6_pkt(pkt):
	return IPv6 in pkt and pkt[IPv6].dst == ul_actual_dst and pkt[IPv6].nh == 17

def is_encaped_icmpv6_pkt(pkt):
	return IPv6 in pkt and pkt[IPv6].dst == ul_actual_dst and pkt[IPv6].nh == 0x29

def is_encaped_icmp_pkt(pkt):
	return IPv6 in pkt and pkt[IPv6].dst == ul_actual_dst and pkt[IPv6].nh == 4 and ICMP in pkt

def is_geneve_encaped_icmp_pkt(pkt):
	return IPv6 in pkt and pkt[IPv6].dst == ul_actual_dst and pkt[IPv6].nh == 17 and ICMP in pkt

# Just wait a bit for the other thread (sniffer/responder) to start listening
def delayed_sendp(packet, interface):
	time.sleep(0.1)
	sendp(packet, iface=interface)
