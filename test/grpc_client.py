# SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
# SPDX-License-Identifier: Apache-2.0

import json
import os
import pytest
import re
import shlex
import socket
import subprocess
import sys
import time
from config import grpc_port


class GrpcError(Exception):
	def __init__(self, errcode, message):
		self.errcode = errcode
		self.message = message
	def __str__(self):
		return f"Error #{self.errcode}: {self.message}";

class GrpcClient:

	def __init__(self, build_path):
		self.cmd = build_path + "/dpservice-cli"
		self.expectedError = 0
		if not os.access(self.cmd, os.X_OK):
			self.cmd = build_path + "/github.com/ironcore-dev/dpservice-cli"
			if not os.access(self.cmd, os.X_OK):
				print(f"""
Missing executable grpc client
To solve this, you have a few options:
 - build one locally and copy it to {build_path}/
 - download one from GitHub manually to {build_path}/
 - use provided download script with your GitHub PAT:
 ./hack/rel_download.sh -dir=build -owner=ironcore-dev -repo=dpservice-cli -pat=<PAT>
""", file=sys.stderr)
				raise RuntimeError("no gRPC client")

	def getClientVersion(self):
		return subprocess.check_output([self.cmd, '-v']).decode('utf-8').strip()

	def expect_error(self, errcode):
		self.expectedError = errcode
		return self

	def _call(self, args):
		expectedError = self.expectedError
		self.expectedError = 0

		print("dpservice-cli", args)
		p = subprocess.run([self.cmd, '-o', 'json'] + shlex.split(args), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		# server errors (retcode 2) are handled as a JSON response too
		if p.returncode != 0 and p.returncode != 2:
			if len(p.stderr):
				print(" !", p.stderr.decode('utf8').strip().replace("\n", "\n ! "))
			raise RuntimeError("Grpc client failed")
		output = p.stdout.decode('utf8').strip()
		if len(output) == 0:
			return None
		print(" >", output.replace("\n", "\n > "))
		response = json.loads(output)
		status = response['status']
		errcode = status['code']
		if errcode != 0:
			assert p.returncode == 2, \
				"Grpc client process returned invalid error value"
			message = status['message']
			assert message, \
				f"dp-service not sending any error message for error code {errcode}"
			if expectedError == errcode:
				return None
			raise GrpcError(errcode, message)
		else:
			assert p.returncode == 0, \
				"Grpc client returned an error value without status"
			if expectedError:
				raise AssertionError(f"Error {expectedError} expected, none received")

		return response

	def _getSpec(self, args):
		response = self._call(args)
		return response['spec'] if response else None

	def _getSpecList(self, args):
		response = self._call(args)
		if not response:
			return None
		specs = []
		for item in response['items']:
			specs.append(item['spec'])
		return specs

	def _getUnderlayRoute(self, args):
		spec = self._getSpec(args)
		return spec['underlay_route'] if spec else None

	def init(self):
		self._call("init")

	def addinterface(self, vm_name, pci, vni, ipv4, ipv6):
		return self._getUnderlayRoute(f"add interface --id={vm_name} --device={pci} --vni={vni} --ipv4={ipv4} --ipv6={ipv6}")

	def getinterface(self, vm_name):
		return self._getSpec(f"get interface --id={vm_name}")

	def delinterface(self, vm_name):
		self._call(f"del interface --id={vm_name}")

	def listinterfaces(self):
		return self._getSpecList("list interfaces")

	def addroute(self, vni, prefix, t_vni, t_ipv6):
		self._call(f"add route --vni={vni} --prefix={prefix} --next-hop-vni={t_vni} --next-hop-ip={t_ipv6}")

	def delroute(self, vni, prefix):
		self._call(f"del route --vni={vni} --prefix={prefix}")

	def listroutes(self, vni):
		return self._getSpecList(f"list routes --vni={vni}")

	def addprefix(self, vm_name, prefix):
		return self._getUnderlayRoute(f"add prefix --interface-id={vm_name} --prefix={prefix}")

	def delprefix(self, vm_name, prefix):
		self._call(f"del prefix --interface-id={vm_name} --prefix={prefix}")

	def listprefixes(self, vm_name):
		return self._getSpecList(f"list prefixes --interface-id={vm_name}")

	def createlb(self, name, vni, vip, portspecs):
		return self._getUnderlayRoute(f"add loadbalancer --id={name} --vni={vni} --vip={vip} --lbports={portspecs}")

	def getlb(self, name):
		return self._getSpec(f"get loadbalancer --id={name}")

	def dellb(self, name):
		self._call(f"delete loadbalancer --id={name}")

	def addlbtarget(self, lb_name, ipv6):
		self._call(f"add lbtarget --lb-id={lb_name} --target-ip={ipv6}")

	def dellbtarget(self, lb_name, ipv6):
		self._call(f"del lbtarget --lb-id={lb_name} --target-ip={ipv6}")

	def listlbtargets(self, lb_name):
		return self._getSpecList(f"list lbtargets --lb-id={lb_name}")

	def addlbprefix(self, vm_name, vip):
		return self._getUnderlayRoute(f"add lbprefix --interface-id={vm_name} --prefix={vip}/32")

	def dellbprefix(self, vm_name, vip):
		self._call(f"del lbprefix --interface-id={vm_name} --prefix={vip}/32")

	def listlbprefixes(self, vm_name):
		return self._getSpecList(f"list lbprefixes --interface-id={vm_name}")

	def addvip(self, vm_name, vip):
		return self._getUnderlayRoute(f"add virtualip --interface-id={vm_name} --vip={vip}")

	def getvip(self, vm_name):
		return self._getSpec(f"get virtualip --interface-id={vm_name}")

	def delvip(self, vm_name):
		self._call(f"del vip --interface-id={vm_name}")

	def addnat(self, vm_name, vip, min_port, max_port):
		return self._getUnderlayRoute(f"add nat --interface-id={vm_name} --nat-ip={vip} --minport={min_port} --maxport={max_port}")

	def getnat(self, vm_name):
		return self._getSpec(f"get nat --interface-id={vm_name}")

	def delnat(self, vm_name):
		self._call(f"del nat --interface-id={vm_name}")

	def listneighnats(self, nat_vip):
		return self._getSpecList(f"list nats --nat-ip={nat_vip} --nat-type=neigh")

	def addneighnat(self, nat_vip, vni, min_port, max_port, t_ipv6):
		self._call(f"add neighnat --nat-ip={nat_vip} --vni={vni} --minport={min_port} --maxport={max_port} --underlayroute={t_ipv6}")

	def delneighnat(self, nat_vip, vni, min_port, max_port):
		self._call(f"del neighnat --nat-ip={nat_vip} --vni={vni} --minport={min_port} --maxport={max_port}")

	def addfwallrule(self, vm_name, rule_id,
				     src_prefix="0.0.0.0/0", dst_prefix="0.0.0.0/0", proto=None,
				     src_port_min=-1, src_port_max=-1, dst_port_min=-1, dst_port_max=-1,
				     action="accept", direction="ingress", priority=None):
		protospec = "" if proto is None else f"--protocol={proto}"
		priospec = "" if priority is None else f"--priority={priority}"
		self._call(f"add fwrule --interface-id={vm_name} --rule-id={rule_id} --src={src_prefix} --dst={dst_prefix} {protospec}"
				  f" --src-port-min={src_port_min} --src-port-max={src_port_max} --dst-port-min={dst_port_min} --dst-port-max={dst_port_max}"
				  f" --action={action} --direction={direction} {priospec}")

	def getfwallrule(self, vm_name, rule_id):
		return self._getSpec(f"get fwrule --interface-id={vm_name} --rule-id={rule_id}")

	def delfwallrule(self, vm_name, rule_id):
		self._call(f"del fwrule --interface-id={vm_name} --rule-id={rule_id}")

	def listfwallrules(self, vm_name):
		return self._getSpecList(f"list fwrules --interface-id={vm_name}")

	def getvni(self, vni):
		return self._getSpec(f"get vni --vni={vni} --vni-type=0")

	def resetvni(self, vni):
		self._call(f"reset vni --vni={vni}")

	@staticmethod
	def port_open():
		with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
			try:
				s.connect(("localhost", grpc_port))
				s.close()
				return True
			except ConnectionRefusedError:
				return False

	@staticmethod
	def wait_for_port():
		for i in range(50):
			if GrpcClient.port_open():
				return
			time.sleep(0.1)
		raise TimeoutError("Waiting for GRPC port timed out")
