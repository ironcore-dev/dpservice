import threading
import pytest
import time
import shlex
import subprocess

from config import *
from helpers import *
from responders import *


def test_ipv4_in_ipv6(add_machine, request_ip_vf0, tun_opt, port_redundancy):

	responder = geneve_in_ipv6_responder if tun_opt == tun_type_geneve else ipv4_in_ipv6_responder
	threading.Thread(target=responder, args=(pf0_tap,)).start()
	if port_redundancy:
		threading.Thread(target=responder, args=(pf1_tap,)).start()

	time.sleep(0.5)
	icmp_echo_pkt = (Ether(dst=pf0_mac, src=vf0_mac, type=0x0800) /
					 IP(dst="192.168.129.5", src="172.32.10.5") /
					 ICMP(type=8))
	sendp(icmp_echo_pkt, iface=vf0_tap)
	pkt_list = sniff(count=1, lfilter=is_icmp_pkt, iface=vf0_tap, timeout=2)
	assert len(pkt_list) == 1

	if port_redundancy:
		time.sleep(0.5)
		icmp_echo_pkt = (Ether(dst=pf0_mac, src=vf0_mac, type=0x0800) /
						 IP(dst="192.168.129.6", src="172.32.10.5") /
						 ICMP(type=8))
		sendp(icmp_echo_pkt, iface=vf0_tap)
		subprocess.run(shlex.split("ip link set dev "+pf1_tap+" up"))
		pkt_list = sniff(count=1, lfilter=is_icmp_pkt, iface=vf0_tap, timeout=2)
		assert len(pkt_list) == 1


def test_ipv6_in_ipv6(add_machine, tun_opt, port_redundancy):
	if port_redundancy:
		pytest.skip("port redundancy not supported in ipv6 path")

	responder = geneve_in_ipv6_responder if tun_opt == tun_type_geneve else ipv6_in_ipv6_responder
	threading.Thread(target=responder).start()

	time.sleep(1)

	icmp_echo_pkt = (Ether(dst=pf0_mac, src=vf0_mac, type=0x86DD) /
					 IPv6(dst="2002::123", src="2001::10", nh=58) /
					 ICMPv6EchoRequest())
	sendp(icmp_echo_pkt, iface=vf0_tap)

	pkt_list = sniff(count=1, lfilter=is_icmpv6echo_pkt, iface=vf0_tap, timeout=2)
	assert len(pkt_list) == 1
