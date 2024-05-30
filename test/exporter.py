import socket
import subprocess
import time

from config import *
from helpers import stop_process

class Exporter:

	def __init__(self, build_path):
		self.cmd = build_path + "/cli/dpservice-exporter/dpservice-exporter"

	def start(self):
		self.process = subprocess.Popen([self.cmd, f"-port={exporter_port}"])

	def stop(self):
		if self.process:
			stop_process(self.process)

	def getVersion(self):
		return subprocess.check_output([self.cmd, '-v']).decode('utf-8').strip()
