# SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
# SPDX-License-Identifier: Apache-2.0

import shlex
import socket
import subprocess
import time
import re
from config import grpc_port


class DpGrpcError(Exception):
	def __init__(self, errcode, message):
		self.errcode = errcode
		self.message = message
	def __str__(self):
		return f"Error #{self.errcode}: {self.message}";

class DpGrpcClient:

	def __init__(self, build_path):
		self.cmd = build_path + "/cli/dp_grpc_client/dp_grpc_client"
		self.re_ipv6 = re.compile(r'(?:^|[\n\r])Received underlay route : ([a-f0-9:]+)(?:$|[\n\r])')
		self.re_error = re.compile(r'(?:^|[\n\r])gRPC call \'[^\']*\' reply with error code ([1-9][0-9][0-9]), message \'[A-Z_]*\'(?:$|[\n\r])')
		self.re_failure = re.compile(r'(?:^|[\n\r])gRPC call \'[^\']*\' failed with error code ([1-9]), message \'[^\']*\'(?:$|[\n\r])')
		self.uuid = None
		self.expectedError = 0
		self.expectFailure = False

	def expect_error(self, errcode):
		self.expectedError = errcode
		return self

	def expect_failure(self):
		self.expectFailure = True
		return self

	def _call(self, args, req_output, negate=False):
		expectedError = self.expectedError
		self.expectedError = 0
		expectFailure = self.expectFailure
		self.expectFailure = False

		ipv6_address = ""
		print("dp_grpc_client", args)
		output = subprocess.check_output([self.cmd] + shlex.split(args)).decode('utf8').strip()
		print(" >", output.replace("\n", "\n > "))

		failure = self.re_failure.search(output)
		if failure:
			return None

		errors = self.re_error.search(output)
		if errors:
			errcode = int(errors.group(1))
			if errcode == expectedError:
				return None
			raise DpGrpcError(errcode, "Legacy gRPC call failed with error")
		else:
			assert not expectedError, f"Legacy gRPC call did not fail with error {expectedError}"

		if negate:
			assert req_output not in output, "Forbidden GRPC output present"
		else:
			assert req_output in output, "Required GRPC output missing"

		return output

	def _getUnderlayRoute(self, args, req_output):
		output = self._call(args, req_output)
		if not output:
			return None
		return self.re_ipv6.search(output).group(1)

	def _getIpSpec(self, ip):
		return f"--ipv6 {ip}" if ':' in ip else f"--ipv4 {ip}"

	def init(self):
		spec = self.getinit()
		if spec:
			self.uuid = spec['uuid']
		else:
			output = self._call("--init", "Initialized")
			match = re.search(r'(?:^|[\n\r])Received UUID ([0-9A-F\-]+)', output)
			self.uuid = match.group(1)

	def getinit(self):
		output = self._call("--is_initialized", "Initialized")
		match = re.search(r'(?:^|[\n\r])Received UUID ([0-9A-F\-]+)', output)
		return { 'uuid': match.group(1) } if match else None

	def getversion(self):
		output = self._call("--getver", "")
		match = re.search(f"(?:^|[\n\r])Got protocol '([^']+)' on service '([^']+)'", output)
		return { 'service_protocol': match.group(1), 'service_version': match.group(2) }

	def addinterface(self, vm_name, pci, vni, ipv4, ipv6, pxe_server=None, ipxe_file=None, preferred_underlay=None):
		cmd = f"--addmachine {vm_name} --vm_pci {pci} --vni {vni} --ipv4 {ipv4} --ipv6 {ipv6}"
		if pxe_server:
			cmd += f" --pxe_ip {pxe_server}"
		if ipxe_file:
			cmd += f" --pxe_str {ipxe_file}"
		if preferred_underlay:
			cmd += f" --underlay {preferred_underlay}"
		return self._getUnderlayRoute(cmd,
			f"Allocated VF for you")

	def getinterface(self, vm_name):
		output = self._call(f"--getmachine {vm_name}", "")
		if not output:
			return None
		match = re.search(r'(?:^|[\n\r])Interface with ipv4 ([0-9\.]+) ipv6 ([0-9a-fA-F:]+) vni ([0-9]+) pci ([^ ]+) underlayroute ([0-9a-fA-F:]+)', output)
		return { 'vni': int(match.group(3)), 'device': match.group(4), 'primary_ipv4': match.group(1), 'primary_ipv6': match.group(2), 'underlay_route': match.group(5), 'metering': {} }

	def delinterface(self, vm_name):
		self._call(f"--delmachine {vm_name}", "Interface deleted")

	def listinterfaces(self):
		output = self._call("--getmachines", "")
		if not output:
			return None
		specs = []
		for match in re.finditer(r'(?:^|[\n\r])Interface [a-zA-Z0-9_]+ ipv4 ([0-9\.]+) ipv6 ([0-9a-fA-F:]+) vni ([0-9]+) pci ([^ ]+) underlayroute ([0-9a-fA-F:]+)', output):
			specs.append({ 'vni': int(match.group(3)), 'device': match.group(4), 'primary_ipv4': match.group(1), 'primary_ipv6': match.group(2), 'underlay_route': match.group(5), 'metering': {} })
		return specs

	def addroute(self, vni, prefix, t_vni, t_ipv6):
		pfx_addr, pfx_len = prefix.split('/')
		__pfx_addr = self._getIpSpec(pfx_addr)
		print(pfx_addr, __pfx_addr)
		self._call(f"--addroute --vni {vni} {__pfx_addr} --length {pfx_len} --t_vni {t_vni} --t_ipv6 {t_ipv6}",
			f"Route ip {pfx_addr} length {pfx_len} vni {vni}")

	def delroute(self, vni, prefix):
		pfx_addr, pfx_len = prefix.split('/')
		__pfx_addr = self._getIpSpec(pfx_addr)
		self._call(f"--delroute --vni {vni} {__pfx_addr} --length {pfx_len}",
			"Route deleted")

	def listroutes(self, vni):
		output = self._call(f"--listroutes --vni {vni}", "")
		if not output:
			return None
		specs = []
		for match in re.finditer(r'(?:^|[\n\r])Route prefix ([0-9\.]+) len ([0-9]+) target vni ([0-9]+) target ipv6 ([0-9a-fA-F:]+)', output):
			specs.append({ "prefix": match.group(1)+'/'+match.group(2), "next_hop": { "vni": int(match.group(3)), "address": match.group(4) } })
		return specs

	def addprefix(self, vm_name, prefix, preferred_underlay=None):
		pfx_addr, pfx_len = prefix.split('/')
		__pfx_addr = self._getIpSpec(pfx_addr)
		cmd = f"--addpfx {vm_name} {__pfx_addr} --length {pfx_len}"
		if preferred_underlay:
			cmd += f" --underlay {preferred_underlay}"
		return self._getUnderlayRoute(cmd, "")

	def delprefix(self, vm_name, prefix):
		pfx_addr, pfx_len = prefix.split('/')
		__pfx_addr = self._getIpSpec(pfx_addr)
		self._call(f"--delpfx {vm_name} {__pfx_addr} --length {pfx_len}", "")

	def listprefixes(self, vm_name):
		output = self._call(f"--listpfx {vm_name}", "")
		if not output:
			return None
		specs = []
		for match in re.finditer(r'(?:^|[\n\r])Route prefix ([0-9a-f\.:]+) len ([0-9]+) underlayroute ([0-9a-fA-F:]+)', output):
			specs.append({ "prefix": match.group(1)+'/'+match.group(2), "underlay_route": match.group(3) })
		specs.sort(key=lambda spec: spec['prefix'])
		return specs

	def createlb(self, name, vni, vip, portspecs, preferred_underlay=None):
		try:
			specs = portspecs.split(',')
			protos = ','.join([ spec.split('/')[0] for spec in specs ])
			ports = ','.join([ spec.split('/')[1] for spec in specs ])
		except:
			return None
		__vip = self._getIpSpec(vip)
		cmd = f"--createlb {name} --vni {vni} {__vip} --port {ports} --protocol {protos}"
		if preferred_underlay:
			cmd += f" --underlay {preferred_underlay}"
		return self._getUnderlayRoute(cmd, f"VIP {vip}, vni {vni}")

	def getlb(self, name):
		output = self._call(f"--getlb {name}", "")
		if not output:
			return None
		match = re.search(r'(?:^|[\n\r])Received LB with vni: ([0-9]+) UL: ([0-9a-fA-F:]+) LB ip: ([0-9a-fA-F:\.]+) with ports: ([^\r\n]+)', output)
		portspecs = match.group(4)
		lbports = []
		for portspec in portspecs.split(' '):
			port, proto = portspec.split(',')
			if proto.lower() == 'tcp':
				proto = 6
			elif proto.lower() == 'udp':
				proto = 17
			elif proto.lower() == 'icmp':
				proto = 1
			lbports.append({ 'protocol': proto, 'port': int(port) })
		return { "vni": int(match.group(1)), "loadbalanced_ip": match.group(3), "loadbalanced_ports": lbports, "underlay_route": match.group(2) }

	def listlbs(self):
		output = self._call(f"--listlbs", "")
		if not output:
			return None
		specs = []
		for match in re.finditer(r'(?:^|[\n\r])Loadbalancer ([^:]+): vni ([0-9]+), ip ([0-9a-fA-F\.:]+), ports ([0-9/a-z ]+), underlayroute ([0-9a-fA-F\:]+)', output):
			portspecs = match.group(4)
			lbports = []
			for portspec in portspecs.split(' '):
				port, proto = portspec.split('/')
				if proto.lower() == 'tcp':
					proto = 6
				elif proto.lower() == 'udp':
					proto = 17
				elif proto.lower() == 'icmp':
					proto = 1
				lbports.append({ 'protocol': proto, 'port': int(port) })
			specs.append({ 'vni': int(match.group(2)), 'loadbalanced_ip': match.group(3), 'loadbalanced_ports': lbports, 'underlay_route': match.group(5) })
		specs.sort(key=lambda spec: spec['loadbalanced_ip'])
		return specs

	def dellb(self, name):
		self._call(f"--dellb {name}", "LB deleted")

	def addlbtarget(self, lb_name, ipv6):
		self._call(f"--addlbvip {lb_name} --t_ipv6 {ipv6}", "LB VIP added")

	def dellbtarget(self, lb_name, ipv6):
		self._call(f"--dellbvip {lb_name} --t_ipv6 {ipv6}", "LB VIP deleted")

	def listlbtargets(self, lb_name):
		output = self._call(f"--listbackips {lb_name}", "")
		if not output:
			return None
		specs = []
		for match in re.finditer(r'(?:^|[\n\r])Backend ip ([0-9a-fA-F:]+)', output):
			specs.append({ 'target_ip': match.group(1) })
		return specs

	def addlbprefix(self, vm_name, vip, preferred_underlay=None):
		prefix, length = vip.split('/')
		__prefix = self._getIpSpec(prefix)
		cmd = f"--addlbpfx {vm_name} {__prefix} --length {length}"
		if preferred_underlay:
			cmd += f" --underlay {preferred_underlay}"
		return self._getUnderlayRoute(cmd, "Received underlay route : ")

	def dellbprefix(self, vm_name, vip):
		prefix, length = vip.split('/')
		__prefix = self._getIpSpec(prefix)
		self._call(f"--dellbpfx {vm_name} {__prefix} --length {length}",
			"LB prefix deleted")

	def listlbprefixes(self, vm_name):
		output = self._call(f"--listlbpfx {vm_name}", "")
		if not output:
			return None
		specs = []
		for match in re.finditer(r'(?:^|[\n\r])LB Route prefix ([0-9a-f\.:]+) len ([0-9]+) underlayroute ([0-9a-fA-F:]+)', output):
			specs.append({ "prefix": match.group(1)+'/'+match.group(2), "underlay_route": match.group(3) })
		specs.sort(key=lambda spec: spec['prefix'])
		return specs

	def addvip(self, vm_name, vip, preferred_underlay=None):
		cmd = f"--addvip {vm_name} --ipv4 {vip}"
		if preferred_underlay:
			cmd += f" --underlay {preferred_underlay}"
		return self._getUnderlayRoute(cmd, "Received underlay route : ")

	def getvip(self, vm_name):
		output = self._call(f"--getvip {vm_name}", "")
		if not output:
			return None
		match = re.search(r'Received VIP ([0-9\.]+) underlayroute ([a-f0-9:]+)', output)
		return { 'vip_ip': match.group(1), 'underlay_route': match.group(2) }

	def delvip(self, vm_name):
		self._call(f"--delvip {vm_name}", "VIP deleted")

	def addnat(self, vm_name, vip, min_port, max_port, preferred_underlay=None):
		cmd = f"--addnat {vm_name} --ipv4 {vip} --min_port {min_port} --max_port {max_port}"
		if preferred_underlay:
			cmd += f" --underlay {preferred_underlay}"
		return self._getUnderlayRoute(cmd, "Received underlay route : ")

	def getnat(self, vm_name):
		output = self._call(f"--getnat {vm_name}", "")
		if not output:
			return None
		match = re.search(r'Received NAT IP ([0-9\.]+) with min port: ([0-9]+) and max port: ([0-9]+) underlay ([a-f0-9:]+)', output)
		return { 'nat_ip': match.group(1), 'underlay_route': match.group(4), 'min_port': int(match.group(2)), 'max_port': int(match.group(3)), 'vni': 0 }

	def delnat(self, vm_name):
		self._call(f"--delnat {vm_name}", "NAT deleted")

	def listlocalnats(self, nat_vip):
		output = self._call(f"--getnatinfo local --ipv4 {nat_vip}", "")
		if not output:
			return None
		specs = []
		for match in re.finditer(r'(?:^|[\n\r]) *[0-9]+: IP ([0-9\.]+), min_port ([0-9]+), max_port ([0-9]+), vni: ([0-9]+)', output):
			specs.append({ 'actual_nat_ip': nat_vip, 'nat_ip': match.group(1), 'min_port': int(match.group(2)), 'max_port': int(match.group(3)), 'vni': int(match.group(4)) })
		return specs

	def listneighnats(self, nat_vip):
		output = self._call(f"--getnatinfo neigh --ipv4 {nat_vip}", "")
		if not output:
			return None
		specs = []
		for match in re.finditer(r'(?:^|[\n\r]) *[0-9]+: min_port ([0-9]+), max_port ([0-9]+), vni ([0-9]+) --> Underlay IPv6 ([a-f0-9:]+)', output):
			specs.append({ 'actual_nat_ip': nat_vip, 'underlay_route': match.group(4), 'min_port': int(match.group(1)), 'max_port': int(match.group(2)), 'vni': int(match.group(3)) })
		return specs

	def addneighnat(self, nat_vip, vni, min_port, max_port, t_ipv6):
		self._call(f"--addneighnat --ipv4 {nat_vip} --vni {vni} --min_port {min_port} --max_port {max_port} --t_ipv6 {t_ipv6}",
			"Neighbor NAT added")

	def delneighnat(self, nat_vip, vni, min_port, max_port):
		self._call(f"--delneighnat --ipv4 {nat_vip} --vni {vni} --min_port {min_port} --max_port {max_port}",
			"Neighbor NAT deleted")

	def addfwallrule(self, vm_name, rule_id,
				     src_prefix="0.0.0.0/0", dst_prefix="0.0.0.0/0", proto=None,
				     src_port_min=-1, src_port_max=-1, dst_port_min=-1, dst_port_max=-1,
				     action="accept", direction="ingress", priority=None):
		protospec = "" if proto is None else f"--protocol {proto}"
		priospec = "" if priority is None else f"--priority {priority}"
		src_addr, src_len = src_prefix.split('/')
		dst_addr, dst_len = dst_prefix.split('/')
		self._call(f"--addfwrule {vm_name} --fw_ruleid {rule_id} --src_ip {src_addr} --src_length {src_len} --dst_ip {dst_addr} --dst_length {dst_len} {protospec}"
				  f" --src_port_min {src_port_min} --src_port_max {src_port_max} --dst_port_min {dst_port_min} --dst_port_max {dst_port_max}"
				  f" --action {action} --direction {direction} {priospec}",
			"Firewall rule created")

	def getfwallrule(self, vm_name, rule_id):
		output = self._call(f"--getfwrule {vm_name} --fw_ruleid {rule_id}", "")
		if not output:
			return None
		match = re.search(rule_id + r' / src_ip: ([0-9\.]+) / src_ip pfx length: ([0-9]+) / dst_ip: ([0-9\.]+) / dst_ip pfx length: ([0-9]+) \n'
						r'protocol: ([a-z]+) / src_port_min: (\-?[0-9]+) / src_port_max: (\-?[0-9]+) / dst_port_min: (\-?[0-9]+) / dst_port_max: (\-?[0-9]+) \n'
						r'direction: ([a-z]+) / action: ([a-z]+)', output)
		return { "id": rule_id,
				 "direction": match.group(10).capitalize(), "action": match.group(11).capitalize(), "priority": 1000,
				 "source_prefix": match.group(1)+'/'+match.group(2), "destination_prefix": match.group(3)+'/'+match.group(4),
				 "protocol_filter": { "Filter": { match.group(5).capitalize(): {
					 "src_port_lower": int(match.group(6)), "src_port_upper": int(match.group(7)),
					 "dst_port_lower": int(match.group(8)), "dst_port_upper": int(match.group(9))
				 } } } }

	def delfwallrule(self, vm_name, rule_id):
		self._call(f"--delfwrule {vm_name} --fw_ruleid {rule_id}",
			"Firewall rule deleted")

	def listfwallrules(self, vm_name):
		output = self._call(f"--listfwrules {vm_name}", "")
		if not output:
			return None
		specs = []
		for match in re.finditer(r'([a-zA-Z0-9\-_]*) / src_ip: ([0-9\.]+) / src_ip pfx length: ([0-9]+) / dst_ip: ([0-9\.]+) / dst_ip pfx length: ([0-9]+) \n'
						r'protocol: ([a-z]+) / src_port_min: (\-?[0-9]+) / src_port_max: (\-?[0-9]+) / dst_port_min: (\-?[0-9]+) / dst_port_max: (\-?[0-9]+) \n'
						r'direction: ([a-z]+) / action: ([a-z]+)', output):
			specs.append({ "id": match.group(1),
				"direction": match.group(11).capitalize(), "action": match.group(12).capitalize(), "priority": 1000,
				"source_prefix": match.group(2)+'/'+match.group(3), "destination_prefix": match.group(4)+'/'+match.group(5),
				"protocol_filter": { "Filter": { match.group(6).capitalize(): {
					"src_port_lower": int(match.group(7)), "src_port_upper": int(match.group(8)),
					"dst_port_lower": int(match.group(9)), "dst_port_upper": int(match.group(10))
				} } } })
		return specs

	def vniinuse(self, vni):
		output = self._call(f"--vni_in_use --vni {vni}", "")
		match = re.search(r'(?:^|[\n\r])Vni: '+str(vni)+' is (.*in use)', output)
		return match.group(1) == 'in use'

	def resetvni(self, vni):
		output = self._call(f"--reset_vni --vni {vni}", "")
		match = re.search(r'(?:^|[\n\r])Vni: '+str(vni)+' (.*resetted)', output)
		return match.group(1) == 'resetted'

	def getvni(self, vni):
		inuse = self.vniinuse(vni)
		return { 'in_use': inuse }
