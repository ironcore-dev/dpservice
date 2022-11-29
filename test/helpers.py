import shlex
import time

from scapy.all import *
from scapy.layers.dhcp import *
from scapy.layers.inet import Ether, ICMP, TCP
from scapy.layers.inet6 import IPv6
from scapy.contrib.geneve import GENEVE

from config import *


def request_ip(interface, macaddr, ipaddr):
	scapy.config.conf.checkIPaddr = False
	answer = dhcp_request(iface=interface, timeout=3)
	msg_type = answer[DHCP].options[0][1]
	if msg_type != 2:
		raise AssertionError(f"DHCP message is not DHCPOFFER (message type: {msg_type})")
	pkt = (Ether(dst=answer[Ether].src) /
		   IP(src=ipaddr, dst=answer[IP].src) /
		   UDP(sport=68, dport=67) /
		   BOOTP(chaddr=macaddr) /
		   DHCP(options=[("message-type", "request"), "end"]))
	answer = srp1(pkt, iface=interface)
	assigned_ip = answer[BOOTP].yiaddr
	if assigned_ip != ipaddr:
		raise AssertionError(f"Wrong address assigned ({assigned_ip})")


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


def delayed_sendp(packet, interface):
	# Just wait a bit for the other thread (sniffer/responder) to start listening
	time.sleep(0.1)
	sendp(packet, iface=interface)


def interface_up(interface):
	cmd = f"ip link set dev {interface} up"
	print(cmd)
	subprocess.check_output(shlex.split(cmd))
