import subprocess
import time
import datetime
import json
import argparse
import sys
import csv
import socket

# Define global settings
START_PORT = 5201
HOST = ''
PORT = 50007

# Function to check if a command exists
def command_exists(cmd):
	return subprocess.call(f"type {cmd}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE) == 0


def determine_address_family(ip_address):
	try:
		socket.inet_aton(ip_address)
		return socket.AF_INET
	except OSError:
		return socket.AF_INET6

# Server functions
pids = []

def terminate_servers():
	for pid in pids:
		subprocess.call(["kill", str(pid)])
		print(f"Terminated iperf3 server process (PID: {pid})")


def start_servers(flow_count):
	for i in range(flow_count):
		port = START_PORT + i
		proc = subprocess.Popen(["iperf3", "-s", "-p", str(port), "--json"], stdout=open(f"iperf3_server_{port}.json", 'w'), stderr=subprocess.PIPE)
		pids.append(proc.pid)
		print(f"Started iperf3 server on port {port}")

def start_server(bind_host,flow_count):
	start_servers(flow_count)
	ip_family = determine_address_family(bind_host)
	with socket.socket(ip_family, socket.SOCK_STREAM) as s:
		s.bind((bind_host, PORT))
		s.listen(1)
		print("TCP server listening for client connection...")
		conn, addr = s.accept()
		with conn:
			print('Connected by', addr)
			conn.sendall("ready".encode('utf-8'))
			conn.recv(1024)  # Wait for any data from client as a signal that tests are done
			print("Client signaled completion of tests.")
			terminate_servers()

# Client functions
def ping(host):
	family = determine_address_family(host)
	success_count = 0
	for _ in range(3):  # Attempt ping 3 times
		try:
			if family == socket.AF_INET:
				output = subprocess.check_output(["ping", "-c", "1", host], stderr=subprocess.STDOUT, universal_newlines=True)
			else:
				output = subprocess.check_output(["ping6", "-c", "1", host], stderr=subprocess.STDOUT, universal_newlines=True)
			print(output)
			success_count += 1
		except subprocess.CalledProcessError as e:
			print(f"Ping failed: {e.output}")
			break  # Exit the loop if any ping attempt fails

	return success_count == 3  # Return True only if all 3 attempts are successful

# manage ping attempts with backoff mechanism
def ping_with_backoff(host, max_attempts=5, max_interval=64):
	attempt = 1
	interval = 1  # Initial backoff interval in seconds

	while attempt <= max_attempts:
		print(f"Attempt {attempt}: pinging {host}")
		success = ping(host)

		if success:
			print("Ping successful!")
			return True
		else:
			print(f"Ping attempt {attempt} failed. Waiting {interval} seconds before retrying...")
			time.sleep(interval)
			interval = min(2 * interval, max_interval)  # Double the interval, but do not exceed max_interval
			attempt += 1

	# If all attempts fail
	print("All ping attempts failed.")
	return False

def connect_with_backoff(host, max_attempts=5, max_interval=32):
	attempt = 1
	interval = 1
	while attempt <= max_attempts:
		try:
			sock = socket.create_connection((host, PORT), timeout=interval)
			print("TCP connection to server established.")
			return sock
		except (ConnectionRefusedError, socket.timeout) as e:
			print(f"Attempt {attempt}: Connection to TCP server failed, retrying in {interval} seconds...")
			time.sleep(interval)
			interval = min(2 * interval, max_interval)
			attempt += 1
	print("All connection attempts failed.")
	sys.exit(1)

def run_iperf3_clients(server_ip, flow_count, run_time, msg_length, round_count, output_file_prefix):
	for round in range(1, round_count + 1):
		print(f"Starting Round {round}")
		pids = []

		if msg_length < 0:
			maximum_seg_length_arg = ''
		else:
			maximum_seg_length_arg = f"-M {msg_length}"

		# Start iperf3 clients and connect to servers
		for i in range(flow_count):
			port = START_PORT + i
			result_file_name = f"test_tcp_{round}_{i}.json"
			cmd = ["iperf3", "-c", server_ip, "-p", str(port), "-t", str(run_time), maximum_seg_length_arg, "--json"]
			with open(result_file_name, 'w') as result_file:
				p = subprocess.Popen(cmd, stdout=result_file)
				pids.append(p)
				print(f"Started iperf3 client connecting to {server_ip} on port {port} (PID: {p.pid})")

		# Wait for all iperf3 client processes to finish
		for p in pids:
			p.wait()

		print(f"All iperf3 client processes have finished for Round {round}.")

		# Sleep before next round, if not the last round
		if round < round_count:
			print("Waiting for 1 second before starting next round...")
			time.sleep(1)

	# Process data after all rounds have been completed
	process_data(round_count, flow_count, output_file_prefix)

def process_data(round_count, flow_count, output_file_prefix):
	aggregated_throughputs_mbps = []
	aggregated_throughputs_gbps = []
	date_str = datetime.datetime.now().strftime('%Y%m%d_%H%M')

	for round in range(1, round_count + 1):
		round_throughput = 0

		for i in range(flow_count):
			result_file_name = f"test_tcp_{round}_{i}.json"
			try:
				with open(result_file_name, 'r') as result_file:
					data = json.load(result_file)
					if 'end' in data and 'sum_received' in data['end']:
						throughput = data['end']['sum_received']['bits_per_second']
						round_throughput += throughput
			except FileNotFoundError:
				print(f"Warning: Result file not found: {result_file_name}")
			except json.JSONDecodeError:
				print(f"Error decoding JSON from file: {result_file_name}")

		round_throughput_mbps = round_throughput / 1_000_000
		round_throughput_gbps = round_throughput / 1_000_000_000
		print(f"Round {round}: Total aggregated throughput: {round_throughput_mbps:.2f} Mbits/sec ({round_throughput_gbps:.3f} Gbits/sec)")
		aggregated_throughputs_mbps.append(round_throughput_mbps)
		aggregated_throughputs_gbps.append(round_throughput_gbps)

	# Calculate and print average throughput after all rounds
	average_throughput_mbps = sum(aggregated_throughputs_mbps) / round_count
	average_throughput_gbps = sum(aggregated_throughputs_gbps) / round_count
	print(f"Average Throughput (Mbits/sec): {average_throughput_mbps:.2f}")
	print(f"Average Throughput (Gbits/sec): {average_throughput_gbps:.3f} Gbits/sec)")

	prefix = output_file_prefix
	if output_file_prefix == '':
		prefix = f"test_tcp_{date_str}"


	# Write aggregated throughputs to a file
	with open(f"{prefix}_{flow_count}_{round_count}.txt", 'w') as output_file:
		for round in range(round_count):
			output_file.write(f"Round {round + 1}: Total aggregated throughput: {aggregated_throughputs_mbps[round]:.2f} Mbits/sec ({aggregated_throughputs_gbps[round]:.3f} Gbits/sec)\n")

	with open(f"{prefix}_{flow_count}_{round_count}.csv", 'w', newline='') as csvfile:
		fieldnames = ['Flow Count', 'Round Number', 'Throughput Mbps', 'Throughput Gbps']
		writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

		writer.writeheader()
		for round in range(round_count):
			throughput_mbps_formatted = f"{aggregated_throughputs_mbps[round]:.2f}"
			throughput_gbps_formatted = f"{aggregated_throughputs_gbps[round]:.3f}"
			writer.writerow({'Flow Count': flow_count, 'Round Number': round, 'Throughput Mbps': throughput_mbps_formatted, 'Throughput Gbps': throughput_gbps_formatted})


def start_client(server_ip, output_file_prefix, flow_count, run_time=10, msg_length=1448, round_count=1):
	if not ping_with_backoff(server_ip, max_attempts=5, max_interval=32):
		print("Server is not reachable.")
		sys.exit(1)

	sock = connect_with_backoff(server_ip, max_attempts=5, max_interval=32)
	ready = sock.recv(1024).decode('utf-8')
	if ready == "ready":
		run_iperf3_clients(server_ip, flow_count, run_time, msg_length, round_count, output_file_prefix)
		sock.sendall("done".encode('utf-8'))
	sock.close()

def test_server(args):
	start_server(args.server_ip, args.flow_count)

def test_client(args):
	start_client(args.server_ip, args.output_file_prefix, args.flow_count, args.run_time, args.payload_length, args.round_count)

def add_shared_subparser_args(parser):
	parser.add_argument('--server-ip', required=True, help="IP address of the iperf3 server.")
	parser.add_argument('--flow-count', type=int, default=1, help="Number of iperf3 concurrent flows to generate.")


def add_arg_parser():
	# Create the top-level parser
	parser = argparse.ArgumentParser(description="Run iperf3 tests as either server or client.")
	subparsers = parser.add_subparsers(help='commands', dest='command')

	# Create the parser for the "server" command
	parser_server = subparsers.add_parser('server', help='Run as an iperf3 server')
	add_shared_subparser_args(parser_server)
	parser_server.set_defaults(func=test_server)

	# Create the parser for the "client" command
	parser_client = subparsers.add_parser('client', help='Run as an iperf3 client')
	add_shared_subparser_args(parser_client)
	parser_client.add_argument('--run-time', type=int, default=10, help="Duration (in seconds) for each iperf3 test.")
	parser_client.add_argument('--payload-length', type=int, default=-1,help="Specify the maximum segment size of a tcp packet.")
	parser_client.add_argument('--round-count', type=int, default=1, help="Number of test rounds to execute.")
	parser_client.add_argument('--output-file-prefix', default='my_test', help="Prefix of output files for both csv and txt.")
	parser_client.set_defaults(func=test_client)

	# Parse the args and call whatever function was selected
	args = parser.parse_args()
	if hasattr(args, 'func'):
		args.func(args)
	else:
		parser.print_help()


if __name__ == "__main__":
	if not command_exists("iperf3"):
		print("iperf3 could not be found")
		sys.exit(1)

	add_arg_parser()

