import shlex
import subprocess


class GrpcClient:

	def __init__(self, build_path):
		self.cmd = build_path + "/test/dp_grpc_client"

	def assert_output(self, args, req_output, negate=False):
		print("dp_grpc_client", args)
		output = subprocess.check_output([self.cmd] + shlex.split(args)).decode('utf8').strip()
		print(" >", output.replace("\n", "\n > "))

		if negate:
			assert req_output not in output, "Forbidden GRPC output present"
		else:
			assert req_output in output, "Required GRPC output missing"

		return output
