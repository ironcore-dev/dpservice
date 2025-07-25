#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
# SPDX-License-Identifier: Apache-2.0

import fcntl
import os
import shlex
import subprocess
from scapy.arch import get_if_hwaddr

from config import *
from grpc_client import GrpcClient
from helpers import interface_init, stop_process


class DpService:

	DP_SERVICE_CONF = "/tmp/dp_service.conf"

	def _get_tap(self, spec):
		return spec.tap_b if self.secondary else spec.tap

	def __init__(self, build_path, port_redundancy, fast_flow_timeout, secondary=False, ha=False,
				 gdb=False, test_virtsvc=False, hardware=False, offloading=False, graphtrace=False):
		self.build_path = build_path
		self.port_redundancy = port_redundancy
		self.hardware = hardware
		self.secondary = secondary

		# HACK lock the lockfile here, so pytest is in control, not the other dpservice
		if secondary:
			self.lockfd = os.open(active_lockfile, os.O_RDWR | os.O_CREAT)
			fcntl.flock(self.lockfd, fcntl.LOCK_EX | fcntl.LOCK_NB)

		if self.hardware:
			if secondary:
				raise ValueError("Hardware tests not available for HA configuration")
			self.reconfigure_tests(DpService.DP_SERVICE_CONF)
		else:
			if offloading:
				raise ValueError("Offloading is only possible when testing on actual hardware")

		self.cmd = ""
		if gdb:
			script_path = os.path.dirname(os.path.abspath(__file__))
			self.cmd = f"gdb -x {script_path}/gdbinit --args "

		self.cmd += f'{self.build_path}/src/dpservice-bin -l 0,1 --log-level=user*:8 --huge-unlink'
		if self.secondary:
			self.cmd += ' --file-prefix=hatest'
		if not self.hardware:
			self.cmd += (f' --no-pci'
						 f' --vdev={PF0.pci},iface={self._get_tap(PF0)},mac="{PF0.mac}"'
						 f' --vdev={PF1.pci},iface={self._get_tap(PF1)},mac="{PF1.mac}"'
						 f' --vdev={VM1.pci},iface={self._get_tap(VM1)},mac="{VM1.mac}"'
						 f' --vdev={VM2.pci},iface={self._get_tap(VM2)},mac="{VM2.mac}"'
						 f' --vdev={VM3.pci},iface={self._get_tap(VM3)},mac="{VM3.mac}"'
						 f' --vdev={VM4.pci},iface={self._get_tap(VM4)},mac="{VM4.mac}"')
		if ha:
			sync_tap = sync_tap_b if secondary else sync_tap_a
			self.cmd += f' --vdev=net_tap_sync,iface={sync_tap}'
		self.cmd += ' --'
		if not self.hardware:
			self.cmd += (f' --pf0={self._get_tap(PF0)}'
						 f' --pf1={self._get_tap(PF1)}'
						 f' --vf-pattern={vf_tap_pattern_b if self.secondary else vf_tap_pattern}'
						 f' --nic-type=tap')
		if ha:
			self.cmd += f' --sync-tap={sync_tap}'
		# HACK only tell the secondary dpservice about the lockfile and keep it locked by pytest
		if secondary:
			self.cmd += f' --active-lockfile={active_lockfile}'
		self.cmd +=	(f' --ipv6={local_ul_ipv6} --enable-ipv6-overlay'
					 f' --dhcp-mtu={dhcp_mtu}'
					 f' --dhcp-dns="{dhcp_dns1}" --dhcp-dns="{dhcp_dns2}"'
					 f' --dhcpv6-dns="{dhcpv6_dns1}" --dhcpv6-dns="{dhcpv6_dns2}"'
					 f' --grpc-port={grpc_port_b if self.secondary else grpc_port}'
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
		if self.process:
			stop_process(self.process)

	def become_active(self):
		if self.secondary and self.lockfd is not None:
			os.close(self.lockfd);
			self.lockfd = None

	def init_ifaces(self, grpc_client):
		interface_init(self._get_tap(VM1))
		interface_init(self._get_tap(VM2))
		interface_init(self._get_tap(VM3))
		interface_init(self._get_tap(PF0))
		if not self.hardware:  # see above
			interface_init(self._get_tap(PF1), self.port_redundancy)
		grpc_client.init()
		dst_ul = 'ul_ipv6_b' if self.secondary else 'ul_ipv6'
		setattr(VM1, dst_ul, grpc_client.addinterface(VM1.name, VM1.pci, VM1.vni, VM1.ip, VM1.ipv6, pxe_server, ipxe_file_name, hostname=VM1.hostname))
		setattr(VM2, dst_ul, grpc_client.addinterface(VM2.name, VM2.pci, VM2.vni, VM2.ip, VM2.ipv6, pxe_server, ipxe_file_name))
		setattr(VM3, dst_ul, grpc_client.addinterface(VM3.name, VM3.pci, VM3.vni, VM3.ip, VM3.ipv6))
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
		pfrepr = "c0pf0"
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
				if key == "pf0":
					PF0.tap = value
				elif key == "pf1":
					PF1.tap = value
				elif key == "vf-pattern":
					# MACs cannot be changed for VFs, use actual values
					VM1.mac = get_if_hwaddr(f"{value}0")
					VM2.mac = get_if_hwaddr(f"{value}1")
					VM3.mac = get_if_hwaddr(f"{value}2")
				elif key == "a-pf0":
					# PCI addresses for VFs are defined by DPDK in this pattern
					pci = value.split(',')[0]
				elif key == "a-pf1":
					# There is a different representor in multiport-eswitch mode and normal mode
					pfrepr = ""
		VM1.tap = self.get_vm_tap(0)
		VM2.tap = self.get_vm_tap(1)
		VM3.tap = self.get_vm_tap(2)
		VM1.pci = f"{pci}_representor_{pfrepr}vf0"
		VM2.pci = f"{pci}_representor_{pfrepr}vf1"
		VM3.pci = f"{pci}_representor_{pfrepr}vf2"
		VM4.pci = f"{pci}_representor_{pfrepr}vf3"

# If run manually:
import argparse
import signal
from helpers import wait_for_port

def silent_sigint(sig, frame):
	pass

if __name__ == '__main__':
	script_path = os.path.dirname(os.path.abspath(__file__))
	parser = argparse.ArgumentParser()
	parser.add_argument("--build-path", action="store", default=f"{script_path}/../../build", help="Path to the root build directory")
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
	wait_for_port(grpc_port, 10)
	if not args.no_init:
		dp_service.init_ifaces(GrpcClient(args.build_path))

	ret = dp_service.process.wait()
	if ret < 0:
		print(f"Killed with signal {-ret}")
	elif ret > 0:
		print(f"Failed with code {ret}")

