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
	options = answer[DHCP].options
	msg_type = next((opt[1] for opt in options if opt[0] == 'message-type'), None)
	if msg_type != 2:
		raise AssertionError(f"DHCP message is not DHCPOFFER (message type: {msg_type})")
	mtu = next((opt[1] for opt in options if opt[0] == 'interface-mtu'), None)
	if mtu != dhcp_mtu:
		raise AssertionError(f"DHCP message does not specify custom MTU ({mtu} instead of {dhcp_mtu})")
	dns_servers = next((opt[1:] for opt in options if opt[0] == 'name_server'), None)
	if not dns_servers or dhcp_dns1 not in dns_servers or dhcp_dns2 not in dns_servers:
		raise AssertionError(f"DHCP message does not specify the right DNS servers: {dns_servers} instead of {dhcp_dns1} and {dhcp_dns2}")
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

def is_udp_pkt(pkt):
	return UDP in pkt

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


def validate_checksums(pkt):
	# NOTE: As checksums are offloaded, tunneled checksums are not computed
	tunneled = type(pkt.getlayer(1)) == IPv6 and IP in pkt
	if IPv6 in pkt:
		assert pkt[IPv6].plen == len(pkt[IPv6])-40, \
			"Invalid IPv6 packet length"
	if IP in pkt:
		assert pkt[IP].len == len(pkt[IP]), \
			"Invalid IPv4 packet length"
		ipv4 = pkt[IP].copy()
		chksum = ipv4.chksum
		if not tunneled or chksum != 0:
			del ipv4.chksum
			ipv4 = IP(raw(ipv4))
			assert ipv4.chksum == chksum, \
				"Invalid IPv4 checksum"
	if TCP in pkt:
		tcp = pkt[TCP].copy()
		chksum = tcp.chksum
		if not tunneled or chksum != 0:
			del tcp.chksum
			tcp = TCP(raw(tcp))
			assert tcp.chksum == chksum, \
				"Invalid TCP checksum"
	if UDP in pkt:
		udp = pkt[UDP].copy()
		chksum = udp.chksum
		if not tunneled or chksum != 0:
			del udp.chksum
			udp = UDP(raw(udp))
			assert udp.chksum == chksum, \
				"Invalid UDP checksum"

def sniff_packet(iface, lfilter, skip=0):
	count = skip+1
	pkt_list = sniff(count=count, lfilter=lfilter, iface=iface, timeout=count*sniff_timeout)
	assert len(pkt_list) == count, \
		f"No reply on {iface}"
	pkt = pkt_list[skip]
	validate_checksums(pkt)
	return pkt
