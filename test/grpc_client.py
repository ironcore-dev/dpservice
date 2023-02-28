import shlex
import socket
import subprocess
import time
import re


class GrpcClient:

	def __init__(self, build_path):
		self.cmd = build_path + "/tools/dp_grpc_client"

	def assert_output(self, args, req_output, negate=False):
		ipv6_address = ""
		print("dp_grpc_client", args)
		output = subprocess.check_output([self.cmd] + shlex.split(args)).decode('utf8').strip()
		print(" >", output.replace("\n", "\n > "))

		if negate:
			assert req_output not in output, "Forbidden GRPC output present"
		else:
			assert req_output in output, "Required GRPC output missing"

		match = re.search(r'\b([a-f0-9:]+)\b', output)

		if match:
			ipv6_address = match.group(1)

		return output, ipv6_address

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
