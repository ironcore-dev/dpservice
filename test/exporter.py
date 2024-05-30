import shlex
import socket
import subprocess
import time

from config import *
from helpers import stop_process

class Exporter:

	def __init__(self, build_path):
		self.cmd = f"{build_path}/cli/dpservice-exporter/dpservice-exporter -port {exporter_port}"

	def start(self):
		self.process = subprocess.Popen(shlex.split(self.cmd))

	def stop(self):
		stop_process(self.process)
