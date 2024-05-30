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
		stop_process(self.process)
