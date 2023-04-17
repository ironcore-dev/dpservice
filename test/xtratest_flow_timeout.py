import pytest

from config import *
from helpers import *
from tcp_tester import TCPTester


def tcp_server_nat_pkt_check(pkt):
	assert pkt[IPv6].dst == router_ul_ipv6, \
		"Request to the wrong outgoing IPv6 address"
	assert pkt[IP].src == nat_vip, \
		f"Packet not coming from NAT's IP"
	assert pkt[IP].dst == public_ip, \
		"Request to a wrong public server IP"
	assert pkt[TCP].dport == 443, \
		"Request to a wrong TCP port"
	assert pkt[TCP].sport == nat_local_min_port, \
		"Failed to use NAT's only single port"

def test_cntrack_nat_timeout_tcp(request, prepare_ipv4, grpc_client, fast_flow_timeout):

	if not fast_flow_timeout:
		pytest.skip("Fast flow timeout needs to be enabled")

	# Only allow one port for this test, so the next call would normally fail (NAT runs out of free ports)
	nat_ul_ipv6 = grpc_client.addnat(VM1.name, nat_vip, nat_local_min_port, nat_local_min_port+1)

	tester = TCPTester(client_vm=VM1, client_port=12344, client_ul_ipv6=nat_ul_ipv6, pf_name=PF0.tap,
					   server_ip=public_ip, server_port=443,
					   server_pkt_check=tcp_server_nat_pkt_check)
	tester.communicate()

	age_out_flows()

	# (the only) NAT port should once again be free now
	tester.client_port = 54321
	tester.request_rst()

	# Same test, but after RST, not FIN-FINACK
	age_out_flows()
	tester.client_port = 54320
	tester.request_rst()

	grpc_client.delnat(VM1.name)


def tcp_server_virtsvc_pkt_check(pkt):
	assert pkt[IPv6].dst == virtsvc_tcp_svc_ipv6, \
		"Request to wrong service IPv6 address"
	assert pkt[TCP].dport == virtsvc_tcp_svc_port, \
		"Request to wrong service TCP port"

def tcp_server_virtsvc_pkt_check_first_port(pkt):
	tcp_server_virtsvc_pkt_check(pkt)
	assert pkt[TCP].sport == 1025, \
		"Request from wrong NAT port"

def tcp_server_virtsvc_pkt_check_second_port(pkt):
	tcp_server_virtsvc_pkt_check(pkt)
	assert pkt[TCP].sport == 1026, \
		"Request from wrong NAT port"

def tcp_server_virtsvc_pkt_check_third_port(pkt):
	tcp_server_virtsvc_pkt_check(pkt)
	assert pkt[TCP].sport == 1027, \
		"Request from wrong NAT port"

def test_virtsvc_tcp_timeout(request, prepare_ipv4, fast_flow_timeout):
	if not request.config.getoption("--virtsvc"):
		pytest.skip("Virtual services not enabled")
	if not fast_flow_timeout:
		pytest.skip("Fast flow timeout needs to be enabled")

	tester = TCPTester(client_vm=VM1, client_port=12345, client_ul_ipv6=router_ul_ipv6, pf_name=PF0.tap,
					   server_ip=virtsvc_tcp_virtual_ip, server_port=virtsvc_tcp_virtual_port,
					   server_pkt_check=tcp_server_virtsvc_pkt_check_first_port,
					   encaped=False)
	tester.communicate()

	# Following connection should be given another port
	tester.client_port = 12346
	tester.server_pkt_check = tcp_server_virtsvc_pkt_check_second_port
	tester.leave_open()

	# After aging, this connection should reuse the first port
	age_out_flows()
	tester.client_port = 12348
	tester.server_pkt_check = tcp_server_virtsvc_pkt_check_first_port
	tester.request_rst()

	# Second port has been left open, thus aging should not work
	tester.client_port = 12349
	tester.server_pkt_check = tcp_server_virtsvc_pkt_check_third_port
	tester.request_rst()

	# Test aging of previous reset
	age_out_flows()
	tester.client_port = 12350
	tester.server_pkt_check = tcp_server_virtsvc_pkt_check_first_port
	tester.request_rst()