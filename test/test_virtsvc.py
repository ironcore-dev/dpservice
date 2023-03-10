import threading
import pytest

from helpers import *
from tcp_tester import TCPTester

udp_used_port = 0

def reply_udp(pf_name):

	global udp_used_port

	pkt = sniff_packet(pf_name, is_udp_pkt)
	assert pkt[IPv6].dst == virtsvc_udp_svc_ipv6, \
		"Request to wrong IPv6 address"
	assert pkt[UDP].dport == virtsvc_udp_svc_port, \
		"Request to wrong UDP port"
	assert udp_used_port != pkt[UDP].sport, \
		"UDP port reused over multiple connections"

	udp_used_port = pkt[UDP].sport

	reply_pkt = (Ether(dst=pkt[Ether].src, src=pkt[Ether].dst, type=0x86DD) /
				 IPv6(dst=router_ul_ipv6, src=pkt[IPv6].dst, nh=17) /
				 UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport))
	delayed_sendp(reply_pkt, pf_name)

def request_udp(l4_port, pf_name):

	threading.Thread(target=reply_udp, args=(pf_name,)).start()

	udp_pkt = (Ether(dst=PF0.mac, src=VM1.mac, type=0x0800) /
			   IP(dst=virtsvc_udp_virtual_ip, src=VM1.ip) /
			   UDP(dport=virtsvc_udp_virtual_port, sport=l4_port))
	delayed_sendp(udp_pkt, VM1.tap)

	pkt = sniff_packet(VM1.tap, is_udp_pkt)
	assert pkt[IP].src == virtsvc_udp_virtual_ip, \
		"Got answer from wrong UDP source port"
	assert pkt[UDP].sport == virtsvc_udp_virtual_port, \
		"Got answer from wrong UDP source port"
	assert pkt[UDP].dport == l4_port, \
		"Got answer to wrong UDP destination port"

def test_virtsvc_udp(request, prepare_ipv4, port_redundancy):
	if not request.config.getoption("--virtsvc"):
		pytest.skip("Virtual services not enabled")
	# port numbers chosen so that they cause the right redirection
	for port in [ 12345, 12346, 12348, 12349, 12350 ]:
		request_udp(port, PF0.tap)
	if port_redundancy:
		for port in [ 12347, 12351, 12354, 12355, 12356 ]:
			request_udp(port, PF1.tap)


def tcp_server_virtsvc_pkt_check(pkt):
	assert pkt[IPv6].dst == virtsvc_tcp_svc_ipv6, \
		"Request to wrong service IPv6 address"
	assert pkt[TCP].dport == virtsvc_tcp_svc_port, \
		"Request to wrong service TCP port"

def test_virtsvc_tcp(request, prepare_ipv4, port_redundancy):
	if not request.config.getoption("--virtsvc"):
		pytest.skip("Virtual services not enabled")

	tester = TCPTester(client_vm=VM1, client_port=12345, client_ul_ipv6=router_ul_ipv6, pf_name=PF0.tap,
					   server_ip=virtsvc_tcp_virtual_ip, server_port=virtsvc_tcp_virtual_port,
					   server_pkt_check=tcp_server_virtsvc_pkt_check,
					   encaped=False)
	tester.communicate()

	# port number chosen so that they cause the right redirection
	if port_redundancy:
		tester.client_port = 54321
		tester.pf_name = PF1.tap
		tester.communicate()

# TODO create a similar test for connection timeout, like NAT has
# TODO move this into a separate file for such tests (require dp-service change)
# This is a test for debugging TCP RST in virtual service implementation
# Without crafted debug setup of the code, this cannot be tested automatically
"""
def disabled_test_virtsvc_tcp_reset(request, prepare_ipv4, port_redundancy):
	if not request.config.getoption("--virtsvc"):
		pytest.skip("Virtual services not enabled")
	tcp_port = 43210
	# tcp_reset()
	request_tcp(tcp_port, "S", PF0.tap)
	request_tcp(tcp_port, "", PF0.tap, payload=TCP_RESET_REQUEST)
"""
