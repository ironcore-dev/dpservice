# SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
# SPDX-License-Identifier: Apache-2.0

import re
import logging
import os
import sys
from termcolor import colored

class MachineLogger:
	def __init__(self, machine_name):
		self.machine_name = machine_name
		self.logger = logging.getLogger(machine_name)
		self.logger.setLevel(logging.INFO)

		handler = logging.StreamHandler(sys.stdout)
		formatter = logging.Formatter('%(message)s')
		handler.setFormatter(formatter)
		self.logger.addHandler(handler)

	def info(self, message):
		colored_message = colored(f"[INFO] [{self.machine_name}] {message}", 'green')
		self.logger.info(colored_message)

	def error(self, message):
		colored_message = colored(f"[ERROR] [{self.machine_name}] {message}", 'red')
		self.logger.error(colored_message)


# string processing functions
def remove_last_empty_line(output):
	lines = output.splitlines()
	if lines and lines[-1] == '':
		lines.pop()
	return '\n'.join(lines)

# result checking functions
def result_checking_ping_failed(result, query):
	return query in result


def result_checking_throughput_higher_than(result, minimum_throughput):
	# Regex to find the "Average Throughput (Gbits/sec):" followed by a number
	match = re.search(
		r"Average Throughput \(Gbits/sec\):\s+(\d+\.\d+)", result)
	if match:
		# Convert the found string to a float
		average_throughput = float(match.group(1))
		# Compare it to the minimum threshold
		if average_throughput >= minimum_throughput:
			return True
		else:
			return False
	else:
		# If no matching throughput is found, handle it accordingly
		return False
