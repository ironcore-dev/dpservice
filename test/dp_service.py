#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
# SPDX-License-Identifier: Apache-2.0

import os
import shlex
import subprocess
from scapy.arch import get_if_hwaddr

from config import *
from grpc_client import GrpcClient
from helpers import interface_init


class DpService:

	DP_SERVICE_CONF = "/tmp/dp_service.conf"

	def __init__(self, build_path, port_redundancy, fast_flow_timeout,
				 gdb=False, test_virtsvc=False, hardware=False, offloading=False, graphtrace=False):
		self.build_path = build_path
		self.port_redundancy = port_redundancy
		self.hardware = hardware

		if self.hardware:
			if self.port_redundancy:
				raise ValueError("Port redundancy is not supported when testing on actual hardware")
			self.reconfigure_tests(DpService.DP_SERVICE_CONF)
		else:
			if offloading:
				raise ValueError("Offloading is only possible when testing on actual hardware")

		self.cmd = ""
		if gdb:
			script_path = os.path.dirname(os.path.abspath(__file__))
			self.cmd = f"gdb -x {script_path}/gdbinit --args "

		self.cmd += f'{self.build_path}/src/dpservice-bin -l 0,1 --log-level=user*:8'
		if not self.hardware:
			self.cmd += (f' --no-pci'
						 f' --vdev={PF0.pci},iface={PF0.tap},mac="{PF0.mac}"'
						 f' --vdev={PF1.pci},iface={PF1.tap},mac="{PF1.mac}"'
						 f' --vdev={VM1.pci},iface={VM1.tap},mac="{VM1.mac}"'
						 f' --vdev={VM2.pci},iface={VM2.tap},mac="{VM2.mac}"'
						 f' --vdev={VM3.pci},iface={VM3.tap},mac="{VM3.mac}"'
						 f' --vdev={VM4.pci},iface={VM4.tap},mac="{VM4.mac}"')
		self.cmd += ' --'
		if not self.hardware:
			self.cmd +=  f' --pf0={PF0.tap} --pf1={PF1.tap} --vf-pattern={vf_tap_pattern} --nic-type=tap'
		self.cmd +=	(f' --ipv6={local_ul_ipv6} --enable-ipv6-overlay'
					 f' --dhcp-mtu={dhcp_mtu}'
					 f' --dhcp-dns="{dhcp_dns1}" --dhcp-dns="{dhcp_dns2}"'
					 f' --grpc-port={grpc_port}'
					  ' --no-stats'
					  ' --color=auto')
		if graphtrace:
			self.cmd += ' --graphtrace-loglevel=1'
		if not offloading:
			self.cmd += ' --no-offload'

		if self.port_redundancy:
			self.cmd += ' --wcmp=50'
		if fast_flow_timeout:
			self.cmd += f' --flow-timeout={flow_timeout}'
		if test_virtsvc:
			self.cmd += (f' --udp-virtsvc="{virtsvc_udp_virtual_ip},{virtsvc_udp_virtual_port},{virtsvc_udp_svc_ipv6},{virtsvc_udp_svc_port}"'
						 f' --tcp-virtsvc="{virtsvc_tcp_virtual_ip},{virtsvc_tcp_virtual_port},{virtsvc_tcp_svc_ipv6},{virtsvc_tcp_svc_port}"')

	def get_cmd(self):
		return self.cmd

	def start(self):
		# for TAPs, command-line arguments are used instead (see above)
		env = {"DP_CONF": ""} if not self.hardware else {}
		self.process = subprocess.Popen(shlex.split(self.cmd), env=env)

	def stop(self):
		self.process.terminate()
		try:
			self.process.wait(5)
		except subprocess.TimeoutExpired:
			self.process.kill()
			self.process.wait()

	def init_ifaces(self, grpc_client):
		interface_init(VM1.tap)
		interface_init(VM2.tap)
		interface_init(VM3.tap)
		interface_init(PF0.tap)
		if not self.hardware:  # see above
			interface_init(PF1.tap, self.port_redundancy)
		grpc_client.init()
		VM1.ul_ipv6 = grpc_client.addinterface(VM1.name, VM1.pci, VM1.vni, VM1.ip, VM1.ipv6)
		VM2.ul_ipv6 = grpc_client.addinterface(VM2.name, VM2.pci, VM2.vni, VM2.ip, VM2.ipv6)
		VM3.ul_ipv6 = grpc_client.addinterface(VM3.name, VM3.pci, VM3.vni, VM3.ip, VM3.ipv6)
		grpc_client.addroute(vni1, neigh_vni1_ov_ip_route, 0, neigh_vni1_ul_ipv6)
		grpc_client.addroute(vni1, neigh_vni1_ov_ipv6_route, 0, neigh_vni1_ul_ipv6)
		grpc_client.addroute(vni1, "0.0.0.0/0", vni1, router_ul_ipv6)
		grpc_client.addroute(vni2, "0.0.0.0/0", vni2, router_ul_ipv6)
		grpc_client.addroute(vni1, "::/0", vni1, router_ul_ipv6)
		grpc_client.addroute(vni2, "::/0", vni2, router_ul_ipv6)

	def attach(self, grpc_client):
		VM1.ul_ipv6 = grpc_client.getinterface(VM1.name)['underlay_route']
		VM2.ul_ipv6 = grpc_client.getinterface(VM2.name)['underlay_route']
		VM3.ul_ipv6 = grpc_client.getinterface(VM3.name)['underlay_route']

	def get_vm_tap(self, idx):
		iface = f"tap{idx}"
		try:
			get_if_hwaddr(iface)
		except Exception as e:
			raise RuntimeError(f"VM interface {iface} is not up and running") from e
		return iface

	def reconfigure_tests(self, cfgfile):
		# Rewrite config values to actual hardware values
		if not os.access(cfgfile, os.R_OK):
			raise OSError(f"Cannot read {cfgfile} to bind to hardware NIC")
		with open(cfgfile, 'r') as config:
			for line in config:
				options = line.split()
				if len(options) != 2:
					continue
				key = options[0]
				value = options[1]
				if key == "pf1":
					# in hardware, PF0 is actually PF1 as it is used as the monitoring interface connected to the real PF0
					PF0.tap = value
				elif key == "vf-pattern":
					# MACs cannot be changed for VFs, use actual values
					VM1.mac = get_if_hwaddr(f"{value}0")
					VM2.mac = get_if_hwaddr(f"{value}1")
					VM3.mac = get_if_hwaddr(f"{value}2")
				elif key == "a-pf0":
					# PCI addresses for VFs are defined by DPDK in this pattern
					pci = value.split(',')[0]
					VM1.pci = f"{pci}_representor_vf0"
					VM2.pci = f"{pci}_representor_vf1"
					VM3.pci = f"{pci}_representor_vf2"
					VM4.pci = f"{pci}_representor_vf3"
		VM1.tap = self.get_vm_tap(0)
		VM2.tap = self.get_vm_tap(1)
		VM3.tap = self.get_vm_tap(2)

# If run manually:
import argparse
import signal

def silent_sigint(sig, frame):
	pass

if __name__ == '__main__':
	script_path = os.path.dirname(os.path.abspath(__file__))
	parser = argparse.ArgumentParser()
	parser.add_argument("--build-path", action="store", default=f"{script_path}/../build", help="Path to the root build directory")
	parser.add_argument("--port-redundancy", action="store_true", help="Set up two physical ports")
	parser.add_argument("--fast-flow-timeout", action="store_true", help="Test with fast flow timeout value")
	parser.add_argument("--virtsvc", action="store_true", help="Enable virtual service tests")
	parser.add_argument("--no-init", action="store_true", help="Do not set interfaces up automatically")
	parser.add_argument("--init-only", action="store_true", help="Only init interfaces of a running service")
	parser.add_argument("--gdb", action="store_true", help="Run service under gdb")
	parser.add_argument("--hw", action="store_true", help="Run on actual hardware NIC instead of virtual TAP devices")
	args = parser.parse_args()

	dp_service = DpService(args.build_path,
						   args.port_redundancy,
						   args.fast_flow_timeout,
						   gdb=args.gdb,
						   test_virtsvc=args.virtsvc,
						   hardware=args.hw)

	if args.init_only:
		dp_service.init_ifaces(GrpcClient(args.build_path))
		exit(0)

	# service handles Ctrl-C directly
	signal.signal(signal.SIGINT, silent_sigint)

	print(dp_service.get_cmd())
	dp_service.start()
	GrpcClient.wait_for_port()
	if not args.no_init:
		dp_service.init_ifaces(GrpcClient(args.build_path))

	ret = dp_service.process.wait()
	if ret < 0:
		print(f"Killed with signal {-ret}")
	elif ret > 0:
		print(f"Failed with code {ret}")
