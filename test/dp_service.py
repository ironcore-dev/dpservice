#!/usr/bin/env python3

import os
import shlex
import subprocess

from config import *
from grpc_client import GrpcClient
from helpers import interface_up


class DpService:

	def __init__(self, build_path, tun_opt, port_redundancy, gdb=False, test_virtsvc=False):
		self.build_path = build_path
		self.port_redundancy = port_redundancy
		self.vm1_ipv6 = None
		self.vm2_ipv6 = None

		self.cmd = ""
		if gdb:
			script_path = os.path.dirname(os.path.abspath(__file__))
			self.cmd = f"gdb -x {script_path}/gdbinit --args "

		self.cmd += (f'{self.build_path}/src/dp_service -l 0,1 --no-pci --log-level=user*:8'
					f' --vdev=net_tap0,iface={pf0_tap},mac="{pf0_mac}"'
					f' --vdev=net_tap1,iface={pf1_tap},mac="{pf1_mac}"'
					f' --vdev=net_tap2,iface={vf0_tap},mac="{vf0_mac}"'
					f' --vdev=net_tap3,iface={vf1_tap},mac="{vf1_mac}"'
					f' --vdev=net_tap4,iface={vf2_tap},mac="{vf2_mac}"'
					 ' --'
					f' --pf0={pf0_tap} --pf1={pf1_tap} --vf-pattern={vf_patt}'
					f' --ipv6={ul_ipv6} --enable-ipv6-overlay'
					f' --dhcp-mtu={dhcp_mtu}'
					f' --dhcp-dns="{dhcp_dns1}" --dhcp-dns="{dhcp_dns2}"'
					 ' --no-offload --no-stats'
					f' --nic-type=tap --overlay-type={tun_opt}')
		if self.port_redundancy:
			self.cmd += ' --wcmp-fraction=0.5'
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
		interface_up(vf0_tap)
		interface_up(vf1_tap)
		interface_up(vf2_tap)
		interface_up(pf0_tap)
		if self.port_redundancy:
			interface_up(pf1_tap)
		grpc_client.init()
		self.vm1_ipv6 = grpc_client.addmachine(vm1_name, "net_tap2", vni, vf0_ip, vf0_ipv6)
		self.vm2_ipv6 = grpc_client.addmachine(vm2_name, "net_tap3", vni, vf1_ip, vf1_ipv6)
		grpc_client.addroute_ipv4(vni, ov_target_pfx, 24, t_vni, ul_actual_dst)
		grpc_client.addroute_ipv6(vni, "2002::123", 128, t_vni, ul_actual_dst)
		grpc_client.addroute_ipv4(vni, "0.0.0.0", 0, vni, ul_actual_dst)

	def attach(self, grpc_client):
		self.vm1_ipv6 = grpc_client.get_ul_ipv6(vm1_name)
		self.vm2_ipv6 = grpc_client.get_ul_ipv6(vm2_name)


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
	parser.add_argument("--no-init", action="store_true", help="Do not set interfaces up automatically")
	parser.add_argument("--init-only", action="store_true", help="Only init interfaces of a running service")
	parser.add_argument("--gdb", action="store_true", help="Run service under gdb")
	args = parser.parse_args()

	dp_service = DpService(args.build_path, args.tun_opt, args.port_redundancy, args.gdb)

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
