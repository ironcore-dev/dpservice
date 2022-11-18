from scapy.all import *
from scapy.layers.dhcp import *
from scapy.layers.inet import Ether, ICMP, TCP
from scapy.layers.inet6 import IPv6
from scapy.contrib.geneve import GENEVE
from scapy.config import conf

import shlex
import subprocess

from config import *


def request_ip(interface):
	conf.checkIPaddr = False
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


def eval_cmd_output(cmd_str, exp_error, negate=False, maxlines=5):
	print("Running command:", cmd_str)

	cmd = shlex.split(cmd_str)
	process = subprocess.Popen(cmd, stdout=subprocess.PIPE, universal_newlines=True)
	count = 0
	first_line = ""
	err_found = False

	while count < maxlines:
		output = process.stdout.readline()
		if not output:
			break;
		line = output.strip()
		print(" > ", line)
		if count == 0:
			first_line = line
		if exp_error in line:
			err_found = True
		count = count + 1
	process.kill()

	if negate:
		if err_found:
			raise AssertionError("Received unexpected string: " + exp_error)
	else:
		if not err_found:
			raise AssertionError("Did not receive expected string: " + exp_error)

	return first_line
