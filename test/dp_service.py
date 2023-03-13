#!/usr/bin/env python3

import os
import shlex
import subprocess

from config import *
from grpc_client import GrpcClient
from helpers import interface_up


class DpService:

	def __init__(self, build_path, tun_opt, port_redundancy, fast_flow_timeout, gdb=False, test_virtsvc=False):
		self.build_path = build_path
		self.port_redundancy = port_redundancy

		self.cmd = ""
		if gdb:
			script_path = os.path.dirname(os.path.abspath(__file__))
			self.cmd = f"gdb -x {script_path}/gdbinit --args "

		self.cmd += (f'{self.build_path}/src/dp_service -l 0,1 --no-pci --log-level=user*:8'
					f' --vdev={PF0.pci},iface={PF0.tap},mac="{PF0.mac}"'
					f' --vdev={PF1.pci},iface={PF1.tap},mac="{PF1.mac}"'
					f' --vdev={VM1.pci},iface={VM1.tap},mac="{VM1.mac}"'
					f' --vdev={VM2.pci},iface={VM2.tap},mac="{VM2.mac}"'
					f' --vdev={VM3.pci},iface={VM3.tap},mac="{VM3.mac}"'
					f' --vdev={VM4.pci},iface={VM4.tap},mac="{VM4.mac}"'
					 ' --'
					f' --pf0={PF0.tap} --pf1={PF1.tap} --vf-pattern={vf_tap_pattern}'
					f' --ipv6={local_ul_ipv6} --enable-ipv6-overlay'
					f' --dhcp-mtu={dhcp_mtu}'
					f' --dhcp-dns="{dhcp_dns1}" --dhcp-dns="{dhcp_dns2}"'
					 ' --no-offload --no-stats'
					f' --grpc-port={grpc_port}'
					f' --nic-type=tap --overlay-type={tun_opt}')
		if self.port_redundancy:
			self.cmd += ' --wcmp-fraction=0.5'
		if fast_flow_timeout:
			self.cmd += f' --flow-timeout={flow_timeout}'
		if test_virtsvc:
			self.cmd += (f' --udp-virtsvc="{virtsvc_udp_virtual_ip},{virtsvc_udp_virtual_port},{virtsvc_udp_svc_ipv6},{virtsvc_udp_svc_port}"'
						 f' --tcp-virtsvc="{virtsvc_tcp_virtual_ip},{virtsvc_tcp_virtual_port},{virtsvc_tcp_svc_ipv6},{virtsvc_tcp_svc_port}"')

	def get_cmd(self):
		return self.cmd

	def start(self):
		self.process = subprocess.Popen(shlex.split(self.cmd), env={"DP_CONF": ""})

	def stop(self):
		self.process.terminate()
		try:
			self.process.wait(5)
		except subprocess.TimeoutExpired:
			self.process.kill()
			self.process.wait()

	def init_ifaces(self, grpc_client):
		interface_up(VM1.tap)
		interface_up(VM2.tap)
		interface_up(VM3.tap)
		interface_up(PF0.tap)
		if self.port_redundancy:
			interface_up(PF1.tap)
		grpc_client.init()
		VM1.ul_ipv6 = grpc_client.addmachine(VM1.name, VM1.pci, VM1.vni, VM1.ip, VM1.ipv6)
		VM2.ul_ipv6 = grpc_client.addmachine(VM2.name, VM2.pci, VM2.vni, VM2.ip, VM2.ipv6)
		VM3.ul_ipv6 = grpc_client.addmachine(VM3.name, VM3.pci, VM3.vni, VM3.ip, VM3.ipv6)
		# TODO confused about the t_vni (is that geneve-only?)
		grpc_client.addroute_ipv4(vni1, neigh_vni1_ov_ip_range, neigh_vni1_ov_ip_range_len, t_vni, neigh_vni1_ul_ipv6)
		grpc_client.addroute_ipv6(vni1, neigh_vni1_ov_ipv6_range, neigh_vni1_ov_ipv6_range_len, t_vni, neigh_vni1_ul_ipv6)
		grpc_client.addroute_ipv4(vni1, "0.0.0.0", 0, vni1, router_ul_ipv6)
		grpc_client.addroute_ipv4(vni2, "0.0.0.0", 0, vni2, router_ul_ipv6)

	def attach(self, grpc_client):
		VM1.ul_ipv6 = grpc_client.get_ul_ipv6(VM1.name)
		VM2.ul_ipv6 = grpc_client.get_ul_ipv6(VM2.name)
		VM3.ul_ipv6 = grpc_client.get_ul_ipv6(VM3.name)


# If run manually:
import argparse
import signal

def silent_sigint(sig, frame):
	pass

if __name__ == '__main__':
	script_path = os.path.dirname(os.path.abspath(__file__))
	parser = argparse.ArgumentParser()
	parser.add_argument("--build-path", action="store", default=f"{script_path}/../build", help="Path to the root build directory")
	parser.add_argument("--tun-opt", action="store", choices=["ipip", "geneve"], default="ipip", help="Underlay tunnel type")
	parser.add_argument("--port-redundancy", action="store_true", help="Set up two physical ports")
	parser.add_argument("--fast-flow-timeout", action="store_true", help="Test with fast flow timeout value")
	parser.add_argument("--virtsvc", action="store_true", help="Enable virtual service tests")
	parser.add_argument("--no-init", action="store_true", help="Do not set interfaces up automatically")
	parser.add_argument("--init-only", action="store_true", help="Only init interfaces of a running service")
	parser.add_argument("--gdb", action="store_true", help="Run service under gdb")
	args = parser.parse_args()

	dp_service = DpService(args.build_path, args.tun_opt, args.port_redundancy, args.fast_flow_timeout, gdb=args.gdb, test_virtsvc=args.virtsvc)

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
