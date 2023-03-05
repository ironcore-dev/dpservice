import shlex
import socket
import subprocess
import time
import re


class GrpcClient:

	def __init__(self, build_path):
		self.cmd = build_path + "/tools/dp_grpc_client"
		self.re_ipv6 = re.compile(r'(?:^|[\n\r])Received underlay route : ([a-f0-9:]+)(?:$|[\n\r])')
		self.re_machine_ipv6 = re.compile(r'(?:^|[\n\r])Interface with ipv4 [0-9\.]+ ipv6 [a-f0-9:]+ vni [0-9]+ pci \w+ underlayroute ([a-f0-9:]+)(?:$|[\n\r])')

	def assert_output(self, args, req_output, negate=False):
		ipv6_address = ""
		print("dp_grpc_client", args)
		output = subprocess.check_output([self.cmd] + shlex.split(args)).decode('utf8').strip()
		print(" >", output.replace("\n", "\n > "))

		if negate:
			assert req_output not in output, "Forbidden GRPC output present"
		else:
			assert req_output in output, "Required GRPC output missing"

		return output

	def find_ipv6(self, text, regex=None):
		if regex is None:
			regex = self.re_ipv6
		match = regex.search(text)
		return match.group(1)

	def init(self):
		self.assert_output("--init", "Init called")

	def addmachine(self, vm_name, pci, vni, ipv4, ipv6):
		output = self.assert_output(f"--addmachine {vm_name} --vm_pci {pci} --vni {vni} --ipv4 {ipv4} --ipv6 {ipv6}",
			f"Allocated VF for you {pci}")
		return self.find_ipv6(output)

	def delmachine(self, vm_name):
		self.assert_output(f"--delmachine {vm_name}", "Interface deleted")

	def get_ul_ipv6(self, vm_name):
		output = self.assert_output(f"--getmachine {vm_name}",
			f" underlayroute ")
		return self.find_ipv6(output, self.re_machine_ipv6)

	def addroute_ipv4(self, vni, ipv4_addr, ipv4_len, t_vni, t_ipv6):
		self.assert_output(f"--addroute --vni {vni} --ipv4 {ipv4_addr} --length {ipv4_len} --t_vni {t_vni} --t_ipv6 {t_ipv6}",
			f"Route ip {ipv4_addr} length {ipv4_len} vni {vni}")

	def delroute_ipv4(self, vni, ipv4_addr, ipv4_len):
		self.assert_output(f"--delroute --vni {vni} --ipv4 {ipv4_addr} --length {ipv4_len}",
			"Route deleted")

	def addroute_ipv6(self, vni, ipv6_addr, ipv6_len, t_vni, t_ipv6):
		self.assert_output(f"--addroute --vni {vni} --ipv6 {ipv6_addr} --length {ipv6_len} --t_vni {t_vni} --t_ipv6 {t_ipv6}",
			f"target ipv6 {ipv6_addr} target vni {t_vni}")

	def addpfx(self, vm_name, ipv4_addr, ipv4_len):
		output = self.assert_output(f"--addpfx {vm_name} --ipv4 {ipv4_addr} --length {ipv4_len}",
			"Received underlay route : ")
		return self.find_ipv6(output)

	def delpfx(self, vm_name, ipv4_addr, ipv4_len):
		self.assert_output(f"--delpfx {vm_name} --ipv4 {ipv4_addr} --length {ipv4_len}",
			"Prefix deleted")

	def createlb(self, name, vni, vip, port, proto):
		output = self.assert_output(f"--createlb {name} --vni {vni} --ipv4 {vip} --port {port} --protocol {proto}",
			f"VIP {vip}, vni {vni}")
		return self.find_ipv6(output)

	def dellb(self, name):
		self.assert_output(f"--dellb {name}", "LB deleted")

	def addlbvip(self, name, ipv6):
		self.assert_output(f"--addlbvip {name} --t_ipv6 {ipv6}", "LB VIP added")

	def dellbvip(self, name, ipv6):
		self.assert_output(f"--dellbvip {name} --t_ipv6 {ipv6}", "LB VIP deleted")

	def addlbpfx(self, name, vip):
		output = self.assert_output(f"--addlbpfx {name} --ipv4 {vip} --length 32",
			"Received underlay route : ")
		return self.find_ipv6(output)

	def dellbpfx(self, name, vip):
		self.assert_output(f"--dellbpfx {name} --ipv4 {vip} --length 32",
			"LB prefix deleted")

	def addvip(self, vm_name, vip):
		output = self.assert_output(f"--addvip {vm_name} --ipv4 {vip}",
			"Received underlay route : ")
		return self.find_ipv6(output)

	def delvip(self, vm_name):
		self.assert_output(f"--delvip {vm_name}", "VIP deleted")

	def addnat(self, vm_name, vip, min_port, max_port):
		output = self.assert_output(f"--addnat {vm_name} --ipv4 {vip} --min_port {min_port} --max_port {max_port}",
			"Received underlay route : ")
		return self.find_ipv6(output)

	def delnat(self, vm_name):
		self.assert_output(f"--delnat {vm_name}", "NAT deleted")

	def addneighnat(self, nat_vip, vni, min_port, max_port, t_ipv6):
		self.assert_output(f"--addneighnat --ipv4 {nat_vip} --vni {vni} --min_port {min_port} --max_port {max_port} --t_ipv6 {t_ipv6}",
			"Neighbor NAT added")

	def delneighnat(self, nat_vip, vni, min_port, max_port):
		self.assert_output(f"--delneighnat --ipv4 {nat_vip} --vni {vni} --min_port {min_port} --max_port {max_port}",
			"Neighbor NAT deleted")

	@staticmethod
	def port_open():
		with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
			try:
				s.connect(("localhost", 1337))  # TODO add to arguments once dp_service supports one too
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
