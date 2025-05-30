# SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
# SPDX-License-Identifier: Apache-2.0

import shlex
import time

from scapy.all import *
from scapy.layers.dhcp import *
from scapy.layers.inet import Ether, ICMP, TCP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6EchoReply, _ICMPv6

from config import *


def request_ip(vm, src_mac=None):
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

	if vm.hostname != None:
		hostname_option = next((opt[1] for opt in options if opt[0] == 'hostname'), None)
		assert hostname_option is not None, "Hostname option not in DHCP reply"
		expected_hostname = vm.hostname
		assert hostname_option.decode('utf-8') == expected_hostname, \
			f"DHCP reply does not specify the correct hostname: {hostname_option.decode('utf-8')} instead of {expected_hostname}"

	pkt = (Ether(src=src_mac, dst=answer[Ether].src) /
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
	if interface.startswith((pf_tap_pattern, vf_tap_pattern, pf_tap_pattern_b, vf_tap_pattern_b)):
		run_command(f"sysctl net.ipv6.conf.{interface}.disable_ipv6=1")
	if enabled:
		run_command(f"ip link set dev {interface} up")


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
	# Need to accept 1337 EtherType which is reflected packet used for --hw tests
	pkt_list = sniff(count=count, iface=iface, timeout=count*sniff_timeout,
					 lfilter=lambda pkt: pkt[Ether].type == 0x1337 or lfilter(pkt))
	assert len(pkt_list) == count, \
		f"No reply on {iface}"
	pkt = pkt_list[skip]
	validate_checksums(pkt)
	# Reconstruct the original packet for --hw tests
	# NOTE: only supports underlay/IPv6 traffic
	if pkt[Ether].type == 0x1337:
		pkt[Ether].type = 0x86DD
		pkt = Ether(pkt.build())
		assert lfilter(pkt), \
			"Reflected packet not of right type"
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


def is_port_open(port):
	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
		try:
			s.connect(("localhost", port))
			s.close()
			return True
		except ConnectionRefusedError:
			return False

def wait_for_port(port, timeout=5):
	for i in range(timeout*10):
		if is_port_open(port):
			return
		time.sleep(0.1)
	raise TimeoutError(f"Waiting for port {port} timed out ({timeout}s)")


def stop_process(process):
	process.terminate()
	try:
		process.wait(5)
	except subprocess.TimeoutExpired:
		process.kill()
		process.wait()


def _send_external_icmp_echo(dst_ipv4, ul_ipv6):
	icmp_pkt = (Ether(dst=PF0.mac, src=ipv6_multicast_mac, type=0x86DD) /
			    IPv6(dst=ul_ipv6, src=router_ul_ipv6, nh=4) /
			    IP(dst=dst_ipv4, src=public_ip) /
			    ICMP(type=8, id=0x0040))
	delayed_sendp(icmp_pkt, PF0.tap)

def external_ping(dst_ipv4, ul_ipv6):
	threading.Thread(target=_send_external_icmp_echo, args=(dst_ipv4, ul_ipv6)).start()
	answer = sniff_packet(PF0.tap, is_icmp_pkt, skip=1)
	assert answer[ICMP].code == 0, \
		"Invalid ICMP echo response"


def _send_external_icmp_echo6(dst_ipv6, ul_ipv6):
	icmp_pkt = (Ether(dst=PF0.mac, src=ipv6_multicast_mac, type=0x86DD) /
				IPv6(dst=ul_ipv6, src=router_ul_ipv6, nh=0x29) /
				IPv6(dst=dst_ipv6, src=public_ipv6, nh=58) /
				ICMPv6EchoRequest())
	delayed_sendp(icmp_pkt, PF0.tap)

def external_ping6(dst_ipv6, ul_ipv6):
	threading.Thread(target=_send_external_icmp_echo6, args=(dst_ipv6, ul_ipv6)).start()
	answer = sniff_packet(PF0.tap, is_icmpv6echo_reply_pkt)
	assert answer[ICMPv6EchoReply].type == 129, \
		"Invalid ICMPv6 echo response"
