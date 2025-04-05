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
import tarfile
import time
import urllib.request
from config import grpc_port


class GrpcClientError(Exception):
	def __init__(self, errtype, errcode, message):
		self.errtype = errtype
		self.errcode = errcode
		self.message = message
	def __str__(self):
		return f"{self.errtype} error #{self.errcode}: {self.message}";

class GrpcError(GrpcClientError):
	def __init__(self, errcode, message):
		super().__init__("gRPC", errcode, message)

class ServiceError(GrpcClientError):
	def __init__(self, errcode, message):
		super().__init__("Service", errcode, message)

class ClientError(GrpcClientError):
	def __init__(self, errcode, message):
		super().__init__("Client", errcode, message)

class GrpcClient:

	def __init__(self, build_path):
		self.uuid = None
		self.expectedError = 0
		self.expectFailure = False
		self.cmd = build_path + "/cli/dpservice-cli/dpservice-cli"
		if not os.access(self.cmd, os.X_OK):
			raise RuntimeError("dpservice-cli is missing (see meson options: 'enable_tests' or 'build_dpservice_cli')")

	def getClientVersion(self):
		return subprocess.check_output([self.cmd, '-v']).decode('utf-8').strip()

	def expect_error(self, errcode):
		self.expectedError = errcode
		return self

	def expect_failure(self):
		self.expectFailure = True
		return self

	def _generateError(self, response):
		source = response['spec']['source']
		status = response['status']
		errcode = status['code']
		message = status['message']
		if source == "server":
			return ServiceError(errcode, message)
		elif source == "grpc":
			return GrpcError(errcode, message)
		elif source == "client":
			return ClientError(errcode, message)
		else:
			raise ValueError(f"gRPC client returned unknown error source '{source}'")

	def _call(self, args):
		expectedError = self.expectedError
		self.expectedError = 0
		expectFailure = self.expectFailure
		self.expectFailure = False

		print("dpservice-cli", args)
		p = subprocess.run([self.cmd, f"--address=localhost:{grpc_port}", '-o', 'json'] + shlex.split(args), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		output = p.stdout.decode('utf8').strip()
		if len(output) == 0:
			raise RuntimeError("Grpc client failed to deliver response")
		print(" >", output.replace("\n", "\n > "))
		response = json.loads(output)
		if response['kind'] == "Error":
			error = self._generateError(response)
			print(error)
			if ((isinstance(error, ServiceError) and error.errcode == expectedError)
				or (isinstance(error, ClientError) and expectFailure)
				or (isinstance(error, GrpcError) and expectFailure)):
				return None
			raise error
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
		spec = self._getSpec("init")
		if spec:
			self.uuid = spec['uuid']

	def getinit(self):
		return self._getSpec("get init")

	def getversion(self):
		return self._getSpec("get version")

	def addinterface(self, vm_name, pci, vni, ipv4, ipv6, pxe_server=None, ipxe_file=None, preferred_underlay=None, hostname=None):
		cmd = f"add interface --id={vm_name} --device={pci} --vni={vni} --ipv4={ipv4} --ipv6={ipv6}"
		if pxe_server:
			cmd += f" --pxe-server={pxe_server}"
		if ipxe_file:
			cmd += f" --pxe-file-name={ipxe_file}"
		if preferred_underlay:
			cmd += f" --underlay={preferred_underlay}"
		if hostname:
			cmd += f" --hostname={hostname}"
		return self._getUnderlayRoute(cmd)

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

	def addprefix(self, vm_name, prefix, preferred_underlay=None):
		cmd = f"add prefix --interface-id={vm_name} --prefix={prefix}"
		if preferred_underlay:
			cmd += f" --underlay={preferred_underlay}"
		return self._getUnderlayRoute(cmd)

	def delprefix(self, vm_name, prefix):
		self._call(f"del prefix --interface-id={vm_name} --prefix={prefix}")

	def listprefixes(self, vm_name):
		return self._getSpecList(f"list prefixes --interface-id={vm_name}")

	def createlb(self, name, vni, vip, portspecs, preferred_underlay=None):
		cmd = f"add loadbalancer --id={name} --vni={vni} --vip={vip} --lbports={portspecs}"
		if preferred_underlay:
			cmd += f" --underlay={preferred_underlay}"
		return self._getUnderlayRoute(cmd)

	def getlb(self, name):
		return self._getSpec(f"get loadbalancer --id={name}")

	def listlbs(self):
		return self._getSpecList("list loadbalancers")

	def dellb(self, name):
		self._call(f"delete loadbalancer --id={name}")

	def addlbtarget(self, lb_name, ipv6):
		self._call(f"add lbtarget --lb-id={lb_name} --target-ip={ipv6}")

	def dellbtarget(self, lb_name, ipv6):
		self._call(f"del lbtarget --lb-id={lb_name} --target-ip={ipv6}")

	def listlbtargets(self, lb_name):
		return self._getSpecList(f"list lbtargets --lb-id={lb_name}")

	def addlbprefix(self, vm_name, prefix, preferred_underlay=None):
		cmd = f"add lbprefix --interface-id={vm_name} --prefix={prefix}"
		if preferred_underlay:
			cmd += f" --underlay={preferred_underlay}"
		return self._getUnderlayRoute(cmd)

	def dellbprefix(self, vm_name, prefix):
		self._call(f"del lbprefix --interface-id={vm_name} --prefix={prefix}")

	def listlbprefixes(self, vm_name):
		return self._getSpecList(f"list lbprefixes --interface-id={vm_name}")

	def addvip(self, vm_name, vip, preferred_underlay=None):
		cmd = f"add virtualip --interface-id={vm_name} --vip={vip}"
		if preferred_underlay:
			cmd += f" --underlay={preferred_underlay}"
		return self._getUnderlayRoute(cmd)

	def getvip(self, vm_name):
		return self._getSpec(f"get virtualip --interface-id={vm_name}")

	def delvip(self, vm_name):
		self._call(f"del vip --interface-id={vm_name}")

	def addnat(self, vm_name, vip, min_port, max_port, preferred_underlay=None):
		cmd = f"add nat --interface-id={vm_name} --nat-ip={vip} --minport={min_port} --maxport={max_port}"
		if preferred_underlay:
			cmd += f" --underlay={preferred_underlay}"
		return self._getUnderlayRoute(cmd)

	def getnat(self, vm_name):
		return self._getSpec(f"get nat --interface-id={vm_name}")

	def delnat(self, vm_name):
		self._call(f"del nat --interface-id={vm_name}")

	def listlocalnats(self, nat_vip):
		return self._getSpecList(f"list nats --nat-ip={nat_vip} --nat-type=local")

	def listneighnats(self, nat_vip):
		return self._getSpecList(f"list nats --nat-ip={nat_vip} --nat-type=neigh")

	def addneighnat(self, nat_vip, vni, min_port, max_port, t_ipv6):
		self._call(f"add neighnat --nat-ip={nat_vip} --vni={vni} --minport={min_port} --maxport={max_port} --underlayroute={t_ipv6}")

	def delneighnat(self, nat_vip, vni, min_port, max_port):
		self._call(f"del neighnat --nat-ip={nat_vip} --vni={vni} --minport={min_port} --maxport={max_port}")

	def addfwallrule(self, vm_name, rule_id,
				     src_prefix="0.0.0.0/0", dst_prefix="0.0.0.0/0", proto=None,
				     src_port_min=-1, src_port_max=-1, dst_port_min=-1, dst_port_max=-1,
				     action="accept", direction="ingress", priority=None,
				     icmp_code=-1, icmp_type=-1):
		protospec = "" if proto is None else f"--protocol={proto}"
		priospec = "" if priority is None else f"--priority={priority}"
		l4spec = f" --src-port-min={src_port_min} --src-port-max={src_port_max} --dst-port-min={dst_port_min} --dst-port-max={dst_port_max}"

		if proto == "icmp":
			l4spec = f"--icmp-code={icmp_code} --icmp-type={icmp_type}"

		self._call(f"add fwrule --interface-id={vm_name} --rule-id={rule_id} --src={src_prefix} --dst={dst_prefix} {protospec}"
				   f" {l4spec} "
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
