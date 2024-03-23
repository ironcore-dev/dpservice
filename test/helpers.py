# SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
# SPDX-License-Identifier: Apache-2.0

import shlex
import time

from scapy.all import *
from scapy.layers.dhcp import *
from scapy.layers.inet import Ether, ICMP, TCP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6EchoReply, _ICMPv6

from config import *


def request_ip(vm):
	scapy.config.conf.checkIPaddr = False
	answer = dhcp_request(iface=vm.tap, timeout=sniff_timeout)
	validate_checksums(answer)
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
		   IP(src=vm.ip, dst=answer[IP].src) /
		   UDP(sport=68, dport=67) /
		   BOOTP(chaddr=vm.mac) /
		   DHCP(options=[("message-type", "request"), "end"]))
	answer = srp1(pkt, iface=vm.tap, timeout=sniff_timeout)
	validate_checksums(answer)
	assigned_ip = answer[BOOTP].yiaddr
	if assigned_ip != vm.ip:
		raise AssertionError(f"Wrong address assigned ({assigned_ip})")


def is_icmp_pkt(pkt):
	return ICMP in pkt

def is_icmpv6_echo_pkt(pkt):
	return ICMPv6EchoRequest in pkt

def is_udp_pkt(pkt):
	return UDP in pkt

def is_ipv6_tcp_pkt(pkt):
	return IPv6 in pkt and TCP in pkt and 'MSS' not in [ option[0] for option in pkt[TCP].options ]

def is_tcp_pkt(pkt):
	return TCP in pkt and 'MSS' not in [ option[0] for option in pkt[TCP].options ]

def is_tcp_vip_src_pkt(pkt):
	return TCP in pkt and pkt[IP].src == vip_vip

def is_icmpv6echo_reply_pkt(pkt):
	return ICMPv6EchoReply in pkt

def is_encaped_icmpv6_pkt(pkt):
	return IPv6 in pkt and pkt[IPv6].nh == 0x29 and ICMPv6EchoRequest in pkt

def is_ipip_pkt(pkt):
	return IPv6 in pkt and pkt[IPv6].nh == 4

def is_encaped_icmp_pkt(pkt):
	return is_ipip_pkt(pkt) and ICMP in pkt


def delayed_sendp(packet, interface):
	# Just wait a bit for the other thread (sniffer/responder) to start listening
	time.sleep(0.1)
	sendp(packet, iface=interface)


def run_command(cmd):
	print(cmd)
	subprocess.check_output(shlex.split(cmd))

def interface_init(interface, enabled=True):
	if enabled:
		run_command(f"ip link set dev {interface} up")
	run_command(f"ip addr flush dev {interface}")


def _validate_length(pkt, original_packet):
	if type(pkt) is IPv6:
		pkt_len = pkt.plen + 40  # ipv6 has payload length instead
	elif type(pkt) in [ IP, UDP, IPerror ]:
		pkt_len = pkt.len
	else:
		# TCP has only header length (data offset), needs IP header to compute it
		# ICMP length is message-dependant
		return
	if pkt_len != len(pkt):
		original_packet.show()
		name = pkt.__class__.__name__
		if type(pkt) is IPv6:
			print(f"{name} payload length {pkt_len-40} != {len(pkt)-40}")
		else:
			print(f"{name} length {pkt_len} != {len(pkt)}")
		assert False, f"Invalid {name} length"

def _validate_checksum(pkt, original_packet):
	# Some packets have checksum, other do not
	if type(pkt) in [ IP, TCP, UDP, ICMP, IPerror ]:
		# scapy has problems computing the right checksum for these
		if type(pkt) is ICMP and pkt.length == 0:
			return
		checksum_field = 'chksum'
	elif isinstance(pkt, _ICMPv6) and hasattr(pkt, 'cksum'):
		checksum_field = 'cksum'
	else:
		return
	# As per RFC, 0 means not present (0xFFFF is actually zero, one's complement hack)
	pkt_checksum = getattr(pkt, checksum_field)
	if pkt_checksum == 0:
		return
	# Force scapy to create a new packet and compute missing (deleted) checksum field
	pkt_copy = pkt.copy()
	delattr(pkt_copy, checksum_field)
	pkt_type = type(pkt)
	pkt_copy = pkt_type(raw(pkt_copy))
	scapy_checksum = getattr(pkt_copy, checksum_field)
	if pkt_checksum != scapy_checksum:
		original_packet.show()
		name = pkt.__class__.__name__
		print(f"{name} checksum {hex(pkt_checksum)} != {hex(scapy_checksum)}")
		assert False, f"Invalid {name} checksum"

def validate_checksums(packet):
	pkt = packet
	if Padding in pkt:
		length = len(pkt) - len(pkt[Padding])
		pkt = pkt.__class__(raw(pkt)[0:length])
	while pkt:
		_validate_length(pkt, packet)
		_validate_checksum(pkt, packet)
		pkt = pkt.payload

def sniff_packet(iface, lfilter, skip=0):
	count = skip+1
	pkt_list = sniff(count=count, lfilter=lfilter, iface=iface, timeout=count*sniff_timeout)
	assert len(pkt_list) == count, \
		f"No reply on {iface}"
	pkt = pkt_list[skip]
	validate_checksums(pkt)
	return pkt


def sniff_tcp_fwall_packet(tap, sniff_tcp_data, negated=False):
	if negated:
		pkt_list = sniff(count=1, lfilter=is_tcp_pkt, iface=tap, timeout=sniff_short_timeout)
		if len(pkt_list) == 0:
			sniff_tcp_data["pkt"] = None
		else:
			sniff_tcp_data["pkt"] = pkt_list[0]
	else:
		sniff_tcp_data["pkt"] = sniff_packet(tap, is_tcp_pkt)


def age_out_flows():
	delay = flow_timeout+1  # timers run every 1s, this should always work
	print(f"Waiting {delay}s for flows to age-out...")
	time.sleep(delay)
