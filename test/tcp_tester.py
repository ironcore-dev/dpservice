from config import *
from helpers import *

class TCPTester:
	TCP_RESET_REQUEST = "Resetme"
	TCP_NORMAL_REQUEST = "Hello"
	TCP_NORMAL_RESPONSE = "Same to you"

	def __init__(self, client_vm, client_port, client_ul_ipv6, pf_name, server_ip, server_port, client_pkt_check=None, server_pkt_check=None, encaped=True):
		self.client_vm = client_vm
		self.client_port = client_port
		self.client_ul_ipv6 = client_ul_ipv6
		self.pf_name = pf_name
		self.server_ip = server_ip
		self.server_port = server_port
		self.client_pkt_check = client_pkt_check
		self.server_pkt_check = server_pkt_check
		self.encaped = encaped

	def reset(self):
		self.tcp_sender_seq = 100
		self.tcp_receiver_seq = 200
		self.tcp_used_port = 0


	def get_ip_layer_response(self, pkt):
		if self.encaped:
			return IPv6(dst=self.client_ul_ipv6, src=pkt[IPv6].dst, nh=4) / IP(dst=pkt[IP].src, src=pkt[IP].dst)
		else:
			return IPv6(dst=self.client_ul_ipv6, src=pkt[IPv6].dst, nh=6)

	def get_server_packet(self):
		pkt = sniff_packet(self.pf_name, is_tcp_pkt)
		assert self.tcp_used_port == 0 or pkt[TCP].sport == self.tcp_used_port, \
			f"Dp-service port changed during communication {pkt[TCP].sport} vs {self.tcp_used_port}"
		self.tcp_used_port = pkt[TCP].sport
		if self.server_pkt_check:
			self.server_pkt_check(pkt)
		return pkt

	def reply_tcp(self):
		pkt = self.get_server_packet()

		# Received ACK only, just end
		if pkt[TCP].flags == "A":
			return

		# Communication is always client-initiated, always ACK
		flags = "A"

		# SYN request needs SYNACK
		if pkt[TCP].flags == "S":
			flags += "S"

		# FIN request needs FINACK
		if "F" in pkt[TCP].flags:
			flags += "F"

		reply_pkt = (Ether(dst=pkt[Ether].src, src=pkt[Ether].dst, type=0x86DD) /
					 self.get_ip_layer_response(pkt) /
					 TCP(dport=pkt[TCP].sport, sport=pkt[TCP].dport, seq=self.tcp_receiver_seq, flags=flags, ack=pkt[TCP].seq+1, options=[("NOP", None)]))
		delayed_sendp(reply_pkt, self.pf_name)

		if flags != "A":
			self.tcp_receiver_seq += 1

		# Application-level reply
		if pkt[TCP].payload != None and len(pkt[TCP].payload) > 0:
			if pkt[TCP].payload == Raw(TCPTester.TCP_RESET_REQUEST):
				reply_pkt = (Ether(dst=pkt[Ether].src, src=pkt[Ether].dst, type=0x86DD) /
							 self.get_ip_layer_response(pkt) /
							 TCP(dport=pkt[TCP].sport, sport=pkt[TCP].dport, seq=self.tcp_receiver_seq, flags="R"))
				delayed_sendp(reply_pkt, self.pf_name)
				return

			reply_pkt = (Ether(dst=pkt[Ether].src, src=pkt[Ether].dst, type=0x86DD) /
						 self.get_ip_layer_response(pkt) /
						 TCP(dport=pkt[TCP].sport, sport=pkt[TCP].dport, seq=self.tcp_receiver_seq, flags="") /
						 Raw(TCPTester.TCP_NORMAL_RESPONSE))
			delayed_sendp(reply_pkt, self.pf_name)
			self.tcp_receiver_seq += len(TCPTester.TCP_NORMAL_RESPONSE)

		# Await ACK
		pkt = self.get_server_packet()
		assert pkt[TCP].flags == "A", \
			"Expected an ACK packet"


	def get_client_packet(self):
		pkt = sniff_packet(self.client_vm.tap, is_tcp_pkt)
		assert pkt[IP].src == self.server_ip, \
			"Got answer from wrong server IP"
		assert pkt[TCP].sport == self.server_port, \
			"Got answer from wrong server TCP port"
		assert pkt[IP].dst == self.client_vm.ip, \
			"Got answer back to wrong client VM IP"
		assert pkt[TCP].dport == self.client_port, \
			"Got answer back to wrong client VM TCP port"
		if self.client_pkt_check:
			client_pkt_check(pkt)
		return pkt

	def request_tcp(self, flags, payload=None):
		server_thread = threading.Thread(target=self.reply_tcp)
		server_thread.start()

		tcp_pkt = (Ether(dst=PF0.mac, src=self.client_vm.mac, type=0x0800) /
				   IP(dst=self.server_ip, src=self.client_vm.ip) /
				   TCP(dport=self.server_port, sport=self.client_port, seq=self.tcp_sender_seq, flags=flags, options=[("NOP", None)]))
		if payload != None:
			tcp_pkt /= Raw(payload)
		delayed_sendp(tcp_pkt, self.client_vm.tap)

		# No reaction to ACK expected
		if flags == "A":
			return

		# Server's reaction to the packet
		self.tcp_sender_seq += 1 if payload is None else len(payload)

		pkt = self.get_client_packet()
		reply_seq = pkt.seq;

		assert "A" in pkt[TCP].flags, \
			"No ACK from server"

		# FIN requested, server should ACK
		if "F" in flags:
			assert pkt[TCP].flags == "FA", \
				"No FINACK from server"

		# When sending payload, ACK is first, then separate reply
		if payload is None:
			reply_seq += 1
		else:
			pkt = self.get_client_packet()
			if "R" in pkt[TCP].flags:
				assert payload is not None and payload == TCPTester.TCP_RESET_REQUEST, \
					"Unexpected connection reset"
				self.reset()
				return
			else:
				assert pkt[TCP].payload == Raw(TCPTester.TCP_NORMAL_RESPONSE), \
					"Bad answer from server"
			reply_seq += len(payload)

		# send ACK
		tcp_pkt = (Ether(dst=PF0.mac, src=self.client_vm.mac, type=0x0800) /
				   IP(dst=self.server_ip, src=self.client_vm.ip) /
				   TCP(dport=self.server_port, sport=self.client_port, flags="A", seq=self.tcp_sender_seq, ack=reply_seq))
		delayed_sendp(tcp_pkt, self.client_vm.tap)

		server_thread.join(timeout=1)
		assert not server_thread.is_alive(), \
			"Server reply thread is stuck"


	# Helper function to start, send data over, and properly end TCP connection
	def communicate(self):
		self.reset()
		# 3-way handshake
		self.request_tcp("S")
		# data
		self.request_tcp("", payload=TCPTester.TCP_NORMAL_REQUEST)
		# close connection
		self.request_tcp("F")

	# Helper function to start, send data, and make the server send RST
	def request_rst(self):
		self.reset()
		self.request_tcp("S")
		self.request_tcp("", payload=TCPTester.TCP_RESET_REQUEST)
