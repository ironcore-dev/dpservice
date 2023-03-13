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
