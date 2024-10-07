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
	'nat_used_port_count', 'firewall_rule_count',
)
HW_IFACE_STATS = (
	'rx_broadcast_bytes', 'rx_broadcast_packets', 'tx_broadcast_bytes', 'tx_broadcast_packets',
	'rx_multicast_bytes', 'rx_multicast_packets', 'tx_multicast_bytes', 'tx_multicast_packets',
	'rx_out_of_buffer',
	'rx_phy_bytes', 'rx_phy_crc_errors', 'rx_phy_discard_packets', 'rx_phy_in_range_len_errors', 'rx_phy_packets', 'rx_phy_symbol_errors',
	'tx_phy_bytes', 'tx_phy_discard_packets', 'tx_phy_errors', 'tx_phy_packets',
	'rx_prio0_buf_discard_packets', 'rx_prio0_cong_discard_packets',
	'rx_prio1_buf_discard_packets', 'rx_prio1_cong_discard_packets',
	'rx_prio2_buf_discard_packets', 'rx_prio2_cong_discard_packets',
	'rx_prio3_buf_discard_packets', 'rx_prio3_cong_discard_packets',
	'rx_prio4_buf_discard_packets', 'rx_prio4_cong_discard_packets',
	'rx_prio5_buf_discard_packets', 'rx_prio5_cong_discard_packets',
	'rx_prio6_buf_discard_packets', 'rx_prio6_cong_discard_packets',
	'rx_prio7_buf_discard_packets', 'rx_prio7_cong_discard_packets',
	'rx_unicast_bytes', 'rx_unicast_packets', 'tx_unicast_bytes', 'tx_unicast_packets',
	'rx_vport_bytes', 'rx_vport_packets', 'tx_vport_bytes', 'tx_vport_packets',
	'rx_wqe_errors',
	'tx_pp_clock_queue_errors', 'tx_pp_jitter', 'tx_pp_missed_interrupt_errors', 'tx_pp_rearm_queue_errors', 'tx_pp_sync_lost', 'tx_pp_timestamp_future_errors', 'tx_pp_timestamp_order_errors', 'tx_pp_timestamp_past_errors', 'tx_pp_wander',
)
HW_PF1_IFACE_STATS = (
	'rx_q1_bytes', 'rx_q1_errors', 'rx_q1_packets', 'tx_q1_bytes', 'tx_q1_packets',
	'rx_q2_bytes', 'rx_q2_errors', 'rx_q2_packets', 'tx_q2_bytes', 'tx_q2_packets',
	'rx_q3_bytes', 'rx_q3_errors', 'rx_q3_packets', 'tx_q3_bytes', 'tx_q3_packets',
	'rx_q4_bytes', 'rx_q4_errors', 'rx_q4_packets', 'tx_q4_bytes', 'tx_q4_packets',
	'rx_q5_bytes', 'rx_q5_errors', 'rx_q5_packets', 'tx_q5_bytes', 'tx_q5_packets',
)
HASH_TABLES = (
	'interface_table',
	'conntrack_table', 'dnat_table', 'snat_table',
	'nat_portmap_table', 'nat_portoverload_table',
	'loadbalancer_table', 'loadbalancer_id_table',
	'vni_table', 'vnf_table', 'reverse_vnf_table',
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
	tel = get_telemetry(f"/dp_service/graph/{key}")
	assert tel is not None, \
		"Missing graph telemetry"
	assert "Node_0_to_255" in tel, \
		f"Missing nodes in {key} graph telemetry"
	# Check for rx-X-0 pattern where X can be any number
	rx_nodes = [node for node in tel["Node_0_to_255"] if re.match(r'rx-\d+-0', node)]

	assert len(rx_nodes) == 6, \
		f"Expected 6 'rx-X-0' nodes, found {len(rx_nodes)} in {key} graph telemetry"


def test_telemetry_graph(request, prepare_ifaces):
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

def test_telemetry_htables(dp_service):
	tel = get_telemetry("/dp_service/table/saturation")
	assert set(tel.keys()) == set(HASH_TABLES) or set(tel.keys()) == set(HASH_TABLES + ('virtsvc_table_0', 'virtsvc_table_1')), \
		"Unexpected hash table saturation info"

def test_telemetry_fwall(prepare_ifaces, grpc_client):
	tel = get_telemetry("/dp_service/firewall/rule_count")
	assert tel == { VM1.name: 0, VM2.name: 0, VM3.name: 0 }, \
		"Unexpected firewall rule count"
	grpc_client.addfwallrule(VM1.name, "vm1-fw1")
	tel = get_telemetry("/dp_service/firewall/rule_count")
	assert tel == { VM1.name: 1, VM2.name: 0, VM3.name: 0 }, \
		"Unexpected firewall rule count"
	grpc_client.delfwallrule(VM1.name, "vm1-fw1")
	tel = get_telemetry("/dp_service/firewall/rule_count")
	assert tel == { VM1.name: 0, VM2.name: 0, VM3.name: 0 }, \
		"Unexpected firewall rule count"

def test_telemetry_exporter(request, prepare_ifaces, start_exporter):
	metrics = urlopen(f"http://localhost:{exporter_port}/metrics").read().decode('utf-8')
	graph_stats, heap_info, interface_stats, htable_saturation = set(), set(), set(), set()
	for metric in metrics.splitlines():
		if metric.startswith('dpdk_graph_stat'):
			graph_stats.add(metric.split('"')[1])
		elif metric.startswith('dpdk_heap_info'):
			heap_info.add(metric.split('"')[1])
		elif metric.startswith('dpdk_interface_stat'):
			interface_stats.add(metric.split('"')[3])
		elif metric.startswith('hash_table_saturation'):
			htable_saturation.add(metric.split('"')[3])
		else:
			assert metric.startswith("#"), \
				f"Unknown exported metric '{metric.split('{')[0]}' found"
	# meson options (e.g. enable_virtual_services) are hard to do in these scripts, so just check manually
	graph_nodes = GRAPH_NODES
	iface_stats = IFACE_STATS
	if 'virtsvc' in graph_stats:
		graph_nodes += ('virtsvc',)
	if request.config.getoption("--hw"):
		iface_stats += HW_IFACE_STATS
		if PF1.tap == "pf1-tap":
			graph_nodes += ('tx-6',)
	if 'rx_q1_bytes' in interface_stats:
		iface_stats += HW_PF1_IFACE_STATS
	assert graph_stats == set(graph_nodes), \
		"Unexpected graph telemetry in exporter output"
	assert heap_info == set(HEAP_INFO), \
		"Unexpected heap info in exporter output"
	assert interface_stats == set(iface_stats) or interface_stats == set(iface_stats + ('virtsvc_used_port_count',)), \
		"Unexpected interface statistics in exporter output"
	assert htable_saturation == set(HASH_TABLES) or htable_saturation == set(HASH_TABLES + ('virtsvc_table_0', 'virtsvc_table_1')), \
		"Unexpected hash table info in exporter output"
