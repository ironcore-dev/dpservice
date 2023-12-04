# SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
# SPDX-License-Identifier: Apache-2.0

import json
import pytest
from helpers import *


BUFSIZE = 10240

def get_telemetry(output, client, node):
	client.send(f"{node},0\n".encode())
	output[node] = json.loads(client.recv(BURSTSIZE).decode())[node]
	json.dumps(output[node])

def get_telemetry(request):
	with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as client:
		client.connect("/var/run/dpdk/rte/dpdk_telemetry.v2")
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
	assert "rx-0-0" in tel["Node_0_to_255"], \
		f"Missing PF0 Rx node in {key} graph telemetry"

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
