import shlex
import socket
import subprocess
import time
import re
from config import grpc_port


class GrpcError(Exception):
	def __init__(self, errcode, message):
		self.errcode = errcode
		self.message = message
	def __str__(self):
		return f"Error #{self.errcode}: {self.message}";

class GrpcClient:

	def __init__(self, build_path):
		self.cmd = build_path + "/tools/dp_grpc_client"
		self.re_ipv6 = re.compile(r'(?:^|[\n\r])Received underlay route : ([a-f0-9:]+)(?:$|[\n\r])')
		self.re_error = re.compile(r'(?:^|[\n\r])Received an error ([1-9][0-9][0-9])(?:$|[\n\r])')
		self.expectedError = 0

	def expect_error(self, errcode):
		self.expectedError = errcode
		return self

	def _call(self, args, req_output, negate=False):
		expectedError = self.expectedError
		self.expectedError = 0

		ipv6_address = ""
		print("dp_grpc_client", args)
		output = subprocess.check_output([self.cmd] + shlex.split(args)).decode('utf8').strip()
		print(" >", output.replace("\n", "\n > "))

		errors = self.re_error.search(output)
		if errors:
			errcode = int(errors.group(1))
			if errcode == expectedError:
				return None
			raise GrpcError(errcode, "Legacy gRPC call failed with error")

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

	def init(self):
		self._call("--init", "Init called")

	def addinterface(self, vm_name, pci, vni, ipv4, ipv6):
		return self._getUnderlayRoute(f"--addmachine {vm_name} --vm_pci {pci} --vni {vni} --ipv4 {ipv4} --ipv6 {ipv6}",
			f"Allocated VF for you {pci}")

	def getinterface(self, vm_name):
		output = self._call(f"--getmachine {vm_name}", "")
		if not output:
			return None
		match = re.search(r'(?:^|[\n\r])Interface with ipv4 ([0-9\.]+) ipv6 ([0-9a-fA-F:]+) vni ([0-9]+) pci ([^ ]+) underlayroute ([0-9a-fA-F:]+)', output)
		return { 'vni': int(match.group(3)), 'device': match.group(4), 'ips': [ match.group(1), match.group(2) ], 'underlayRoute': match.group(5) }

	def delinterface(self, vm_name):
		self._call(f"--delmachine {vm_name}", "Interface deleted")

	def listinterfaces(self):
		output = self._call("--getmachines", "")
		if not output:
			return None
		specs = []
		for match in re.finditer(r'(?:^|[\n\r])Interface [a-zA-Z0-9_]+ ipv4 ([0-9\.]+) ipv6 ([0-9a-fA-F:]+) vni ([0-9]+) pci ([^ ]+) underlayroute ([0-9a-fA-F:]+)', output):
			specs.append({ 'vni': int(match.group(3)), 'device': match.group(4), 'ips': [ match.group(1), match.group(2) ], 'underlayRoute': match.group(5) })
		return specs

	def addroute(self, vni, prefix, t_vni, t_ipv6):
		pfx_addr, pfx_len = prefix.split('/')
		if ':' in pfx_addr:
			self._call(f"--addroute --vni {vni} --ipv6 {pfx_addr} --length {pfx_len} --t_vni {t_vni} --t_ipv6 {t_ipv6}",
				f"target ipv6 {pfx_addr} target vni {t_vni}")
		else:
			self._call(f"--addroute --vni {vni} --ipv4 {pfx_addr} --length {pfx_len} --t_vni {t_vni} --t_ipv6 {t_ipv6}",
				f"Route ip {pfx_addr} length {pfx_len} vni {vni}")

	def delroute(self, vni, prefix):
		pfx_addr, pfx_len = prefix.split('/')
		ipver = '--ipv6' if ':' in pfx_addr else '--ipv4'
		self._call(f"--delroute --vni {vni} {ipver} {pfx_addr} --length {pfx_len}",
			"Route deleted")

	def listroutes(self, vni):
		output = self._call(f"--listroutes --vni {vni}", "")
		if not output:
			return None
		specs = []
		for match in re.finditer(r'(?:^|[\n\r])Route prefix ([0-9\.]+) len ([0-9]+) target vni ([0-9]+) target ipv6 ([0-9a-fA-F:]+)', output):
			specs.append({ "vni": vni, "prefix": match.group(1)+'/'+match.group(2), "nextHop": { "vni": int(match.group(3)), "ip": match.group(4) } })
		return specs

	def addprefix(self, vm_name, prefix):
		pfx_addr, pfx_len = prefix.split('/')
		return self._getUnderlayRoute(f"--addpfx {vm_name} --ipv4 {pfx_addr} --length {pfx_len}", "")

	def delprefix(self, vm_name, prefix):
		pfx_addr, pfx_len = prefix.split('/')
		self._call(f"--delpfx {vm_name} --ipv4 {pfx_addr} --length {pfx_len}", "")

	def listprefixes(self, vm_name):
		output = self._call(f"--listpfx {vm_name}", "")
		if not output:
			return None
		specs = []
		for match in re.finditer(r'(?:^|[\n\r])Route prefix ([0-9\.]+) len ([0-9]+) underlayroute ([0-9a-fA-F:]+)', output):
			specs.append({ "prefix": match.group(1)+'/'+match.group(2), "underlayRoute": match.group(3) })
		return specs

	def createlb(self, name, vni, vip, portspecs):
		proto, port = portspecs.split('/')
		return self._getUnderlayRoute(f"--createlb {name} --vni {vni} --ipv4 {vip} --port {port} --protocol {proto}",
			f"VIP {vip}, vni {vni}")

	def getlb(self, name):
		output = self._call(f"--getlb {name}", "")
		if not output:
			return None
		match = re.search(r'(?:^|[\n\r])Received LB with vni: ([0-9]+) UL: ([0-9a-fA-F:]+) LB ip: ([0-9\.]+) with ports: ([^\r\n]+)', output)
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
		return { "vni": int(match.group(1)), "lbVipIP": match.group(3), "lbports": lbports, "underlayRoute": match.group(2) }

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
			specs.append({ 'targetIP': match.group(1) })
		return specs

	def addlbprefix(self, vm_name, vip):
		return self._getUnderlayRoute(f"--addlbpfx {vm_name} --ipv4 {vip} --length 32",
			"Received underlay route : ")

	def dellbprefix(self, vm_name, vip):
		self._call(f"--dellbpfx {vm_name} --ipv4 {vip} --length 32",
			"LB prefix deleted")

	def listlbprefixes(self, vm_name):
		output = self._call(f"--listlbpfx {vm_name}", "")
		if not output:
			return None
		specs = []
		for match in re.finditer(r'(?:^|[\n\r])LB Route prefix ([0-9\.]+) len ([0-9]+) underlayroute ([0-9a-fA-F:]+)', output):
			specs.append({ "prefix": match.group(1)+'/'+match.group(2), "underlayRoute": match.group(3) })
		return specs

	def addvip(self, vm_name, vip):
		return self._getUnderlayRoute(f"--addvip {vm_name} --ipv4 {vip}",
			"Received underlay route : ")

	def getvip(self, vm_name):
		output = self._call(f"--getvip {vm_name}", "")
		if not output:
			return None
		match = re.search(r'Received VIP ([0-9\.]+) underlayroute ([a-f0-9:]+)', output)
		return { 'vipIP': match.group(1), 'underlayRoute': match.group(2) }

	def delvip(self, vm_name):
		self._call(f"--delvip {vm_name}", "VIP deleted")

	def addnat(self, vm_name, vip, min_port, max_port):
		return self._getUnderlayRoute(f"--addnat {vm_name} --ipv4 {vip} --min_port {min_port} --max_port {max_port}",
			"Received underlay route : ")

	def getnat(self, vm_name):
		output = self._call(f"--getnat {vm_name}", "")
		if not output:
			return None
		match = re.search(r'Received NAT IP ([0-9\.]+) with min port: ([0-9]+) and max port: ([0-9]+) underlay ([a-f0-9:]+)', output)
		return { 'natVIPIP': match.group(1), 'underlayRoute': match.group(4), 'minPort': int(match.group(2)), 'maxPort': int(match.group(3)) }

	def delnat(self, vm_name):
		self._call(f"--delnat {vm_name}", "NAT deleted")

	def getnatinfo(self, nat_vip, info_type):
		output = self._call(f"--getnatinfo {info_type} --ipv4 {nat_vip}", "")
		if not output:
			return None
		specs = []
		for match in re.finditer(r'(?:^|[\n\r]) *[0-9]+: min_port ([0-9]+), max_port ([0-9]+) --> Underlay IPv6 ([a-f0-9:]+)(?:$|[\n\r])', output):
			specs.append({ 'natVIPIP': nat_vip, 'underlayRoute': match.group(3), 'minPort': int(match.group(1)), 'maxPort': int(match.group(2)) })
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
			"Add FirewallRule called")

	def getfwallrule(self, vm_name, rule_id):
		output = self._call(f"--getfwrule {vm_name} --fw_ruleid {rule_id}", "")
		if not output:
			return None
		match = re.search(rule_id + r' / src_ip: ([0-9\.]+) / src_ip pfx length: ([0-9]+) / dst_ip: ([0-9\.]+) / dst_ip pfx length: ([0-9]+) \n'
						r'protocol: ([a-z]+) / src_port_min: (\-?[0-9]+) / src_port_max: (\-?[0-9]+) / dst_port_min: (\-?[0-9]+) / dst_port_max: (\-?[0-9]+) \n'
						r'direction: ([a-z]+) / action: ([a-z]+)', output)
		return { "trafficDirection": match.group(10).capitalize(), "firewallAction": match.group(11).capitalize(), "priority": 1000, "ipVersion": "IPv4",
				 "sourcePrefix": match.group(1)+'/'+match.group(2), "destinationPrefix": match.group(3)+'/'+match.group(4),
				 "protocolFilter": { "Filter": { match.group(5).capitalize(): {
					 "srcPortLower": int(match.group(6)), "srcPortUpper": int(match.group(7)), "dstPortLower": int(match.group(8)), "dstPortUpper": int(match.group(9))
				 } } } }

	def delfwallrule(self, vm_name, rule_id):
		self._call(f"--delfwrule {vm_name} --fw_ruleid {rule_id}",
			"Firewall Rule Deleted")

	def listfwallrules(self, vm_name):
		output = self._call(f"--listfwrules {vm_name}", "")
		if not output:
			return None
		specs = []
		for match in re.finditer(r' / src_ip: ([0-9\.]+) / src_ip pfx length: ([0-9]+) / dst_ip: ([0-9\.]+) / dst_ip pfx length: ([0-9]+) \n'
						r'protocol: ([a-z]+) / src_port_min: (\-?[0-9]+) / src_port_max: (\-?[0-9]+) / dst_port_min: (\-?[0-9]+) / dst_port_max: (\-?[0-9]+) \n'
						r'direction: ([a-z]+) / action: ([a-z]+)', output):
			specs.append({
				"trafficDirection": match.group(10).capitalize(), "firewallAction": match.group(11).capitalize(), "priority": 1000, "ipVersion": "IPv4",
				"sourcePrefix": match.group(1)+'/'+match.group(2), "destinationPrefix": match.group(3)+'/'+match.group(4),
				"protocolFilter": { "Filter": { match.group(5).capitalize(): {
					"srcPortLower": int(match.group(6)), "srcPortUpper": int(match.group(7)), "dstPortLower": int(match.group(8)), "dstPortUpper": int(match.group(9))
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
