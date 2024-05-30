# SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
# SPDX-License-Identifier: Apache-2.0

import json
import pytest
from urllib.request import urlopen

from exporter import Exporter
from helpers import *


BUFSIZE = 10240
TELEMETRY_SOCKET = "/var/run/dpdk/rte/dpdk_telemetry.v2"

GRAPH_NODES = (
	'rx-0-0', 'rx-1-0', 'rx-2-0', 'rx-3-0', 'rx-4-0', 'rx-5-0', 'rx_periodic',
	'arp', 'cls', 'conntrack', 'dhcp', 'dhcpv6', 'dnat', 'drop', 'firewall', 'lb', 'packet_relay', 'snat',
	'ipip_decap', 'ipip_encap', 'ipv4_lookup', 'ipv6_lookup', 'ipv6_nd',
	'tx-0', 'tx-1', 'tx-2', 'tx-3', 'tx-4', 'tx-5',
)
HEAP_INFO = ( 'Heap_id', 'Heap_size', 'Alloc_count', 'Free_count', 'Alloc_size', 'Free_size', 'Greatest_free_size' )
IFACE_STATS = (
	'rx_q0_errors', 'rx_q0_bytes', 'tx_q0_bytes', 'rx_q0_packets', 'tx_q0_packets',
	'rx_good_bytes', 'tx_good_bytes', 'rx_good_packets', 'tx_good_packets',
	'rx_errors', 'tx_errors', 'rx_missed_errors', 'rx_mbuf_allocation_errors',
	'nat_used_port_count',
)

def get_telemetry(request):
	with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as client:
		client.connect(TELEMETRY_SOCKET)
		client.recv(BUFSIZE)
		client.send(f"{request},0\n".encode())
		response = json.loads(client.recv(BUFSIZE).decode())[request]
		client.close()
	return response

def check_tel_graph(key):
	expected_tel_rx_node_count = 6
	tel = get_telemetry(f"/dp_service/graph/{key}")
	assert tel is not None, \
		"Missing graph telemetry"
	assert "Node_0_to_255" in tel, \
		f"Missing nodes in {key} graph telemetry"
	# Check for rx-X-0 pattern where X can be any number
	rx_nodes = [node for node in tel["Node_0_to_255"] if re.match(r'rx-\d+-0', node)]

	assert len(rx_nodes) == expected_tel_rx_node_count, \
		f"Expected {expected_tel_rx_node_count} 'rx-X-0' nodes, found {len(rx_nodes)} in {key} graph telemetry"


def test_telemetry_graph(prepare_ifaces):
	check_tel_graph("obj_count")
	check_tel_graph("call_count")
	check_tel_graph("cycle_count")
	check_tel_graph("realloc_count")

def test_telemetry_nat(prepare_ifaces):
	tel = get_telemetry("/dp_service/nat/used_port_count")
	assert tel is not None, \
		"Missing NAT telemetry"
	assert VM1.name in tel and VM2.name in tel and VM3.name in tel, \
		"Running VMs not present in NAT telemetry"

def test_telemetry_virtsvc(request, prepare_ifaces):
	if not request.config.getoption("--virtsvc"):
		pytest.skip("Virtual services not enabled")
	tel = get_telemetry("/dp_service/virtsvc/used_port_count")
	assert tel is not None, \
		"Missing UDP virtual services telemetry"
	assert f"UDP:{virtsvc_udp_virtual_ip}:{virtsvc_udp_virtual_port}" in tel, \
		"Missing UDP virtual service port count"
	assert f"TCP:{virtsvc_tcp_virtual_ip}:{virtsvc_tcp_virtual_port}" in tel, \
		"Missing UDP virtual service port count"

def test_telemetry_exporter(prepare_ifaces, start_exporter):
	metrics = urlopen(f"http://localhost:{exporter_port}/metrics").read().decode('utf-8')
	graph_stats, heap_info, interface_stats = set(), set(), set()
	for metric in metrics.splitlines():
		if metric.startswith('dpdk_graph_stat'):
			graph_stats.add(metric.split('"')[1])
		elif metric.startswith('dpdk_heap_info'):
			heap_info.add(metric.split('"')[1])
		elif metric.startswith('dpdk_interface_stat'):
			interface_stats.add(metric.split('"')[3])
	assert graph_stats == set(GRAPH_NODES) or graph_stats == set(GRAPH_NODES + ('virtsvc',)), \
		"Unexpected graph telemetry in exporter output"
	assert heap_info == set(HEAP_INFO), \
		"Unexpected heap info in exporter output"
	assert interface_stats == set(IFACE_STATS) or interface_stats == set(IFACE_STATS + ('virtsvc_used_port_count',)), \
		"Unexpected interface statistics in exporter output"
