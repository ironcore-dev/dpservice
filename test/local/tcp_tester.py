# SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
# SPDX-License-Identifier: Apache-2.0

from config import *
from helpers import *

class _TCPTester:
	TCP_RESET_REQUEST = "Resetme"
	TCP_NORMAL_REQUEST = "Hello"
	TCP_NORMAL_RESPONSE = "Same to you"

	TCP_SYN_NORMAL = 0
	TCP_SYN_RETRANSMIT = 1
	TCP_SYN_SCAN = 2

	def __init__(self, client_tap, client_mac, client_ip, client_port,
					   server_tap, server_mac, server_ip, server_port,
					   client_pkt_check=None, server_pkt_check=None):
		self.client_tap = client_tap
		self.client_mac = client_mac
		self.client_ip = client_ip
		self.client_port = client_port
		self.server_tap = server_tap
		self.server_mac = server_mac
		self.server_ip = server_ip
		self.server_port = server_port
		self.client_pkt_check = client_pkt_check
		self.server_pkt_check = server_pkt_check

	def reset(self):
		self.tcp_sender_seq = 100
		self.tcp_receiver_seq = 200
		self.tcp_used_port = 0

	def get_server_l3_reply(self, pkt):
		raise NotImplementedError("This base implementation needs to be overriden")

	def get_server_packet(self):
		pkt = sniff_packet(self.server_tap, is_tcp_pkt)
		assert self.tcp_used_port == 0 or pkt[TCP].sport == self.tcp_used_port, \
			f"Dp-service port changed during communication {pkt[TCP].sport} vs {self.tcp_used_port}"
		self.tcp_used_port = pkt[TCP].sport
		if self.server_pkt_check:
			self.server_pkt_check(pkt)
		return pkt

	def reply_tcp(self, syn_style):
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

		reply_pkt = (self.get_server_l3_reply(pkt) /
					 TCP(dport=pkt[TCP].sport, sport=pkt[TCP].dport, seq=self.tcp_receiver_seq, flags=flags, ack=pkt[TCP].seq+1, options=[("NOP", None)]))
		delayed_sendp(reply_pkt, self.server_tap)

		if syn_style == _TCPTester.TCP_SYN_RETRANSMIT:
			delayed_sendp(reply_pkt, self.server_tap)
			return

		if flags != "A":
			self.tcp_receiver_seq += 1

		# Application-level reply
		payload = pkt[TCP].payload
		if payload != None and len(payload) > 0:
			if Padding in payload:
				length = len(payload) - len(payload[Padding])
				payload = payload.__class__(raw(payload)[0:length])
			if payload == Raw(_TCPTester.TCP_RESET_REQUEST):
				reply_pkt = (self.get_server_l3_reply(pkt) /
							 TCP(dport=pkt[TCP].sport, sport=pkt[TCP].dport, seq=self.tcp_receiver_seq, flags="R"))
				delayed_sendp(reply_pkt, self.server_tap)
				return
			elif payload == Raw(_TCPTester.TCP_NORMAL_REQUEST):
				reply_pkt = (self.get_server_l3_reply(pkt) /
							 TCP(dport=pkt[TCP].sport, sport=pkt[TCP].dport, seq=self.tcp_receiver_seq, flags="") /
							 Raw(_TCPTester.TCP_NORMAL_RESPONSE))
				delayed_sendp(reply_pkt, self.server_tap)
				self.tcp_receiver_seq += len(_TCPTester.TCP_NORMAL_RESPONSE)
				# and continue with ACK

		if syn_style != _TCPTester.TCP_SYN_NORMAL:
			return

		# Await ACK
		pkt = self.get_server_packet()
		assert pkt[TCP].flags == "A", \
			"Expected an ACK packet"


	def get_client_packet(self):
		pkt = sniff_packet(self.client_tap, is_tcp_pkt)
		assert pkt[IP].src == self.server_ip, \
			"Got answer from wrong server IP"
		assert pkt[TCP].sport == self.server_port, \
			"Got answer from wrong server TCP port"
		assert pkt[IP].dst == self.client_ip, \
			"Got answer back to wrong client VM IP"
		assert pkt[TCP].dport == self.client_port, \
			"Got answer back to wrong client VM TCP port"
		if self.client_pkt_check:
			client_pkt_check(pkt)
		return pkt

	def request_tcp(self, flags, payload=None, syn_style=TCP_SYN_NORMAL):
		server_thread = threading.Thread(target=self.reply_tcp, args=(syn_style,))
		server_thread.start()

		tcp_pkt = (Ether(dst=self.server_mac, src=self.client_mac, type=0x0800) /
				   IP(dst=self.server_ip, src=self.client_ip) /
				   TCP(dport=self.server_port, sport=self.client_port, seq=self.tcp_sender_seq, flags=flags, options=[("NOP", None)]))
		if payload != None:
			tcp_pkt /= Raw(payload)
		delayed_sendp(tcp_pkt, self.client_tap)

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
				assert payload is not None and payload == _TCPTester.TCP_RESET_REQUEST, \
					"Unexpected connection reset"
				self.reset()
				return
			else:
				assert pkt[TCP].payload == Raw(_TCPTester.TCP_NORMAL_RESPONSE), \
					"Bad answer from server"
			reply_seq += len(payload)

		if syn_style != _TCPTester.TCP_SYN_NORMAL:
			return

		# send ACK
		tcp_pkt = (Ether(dst=self.server_mac, src=self.client_mac, type=0x0800) /
				   IP(dst=self.server_ip, src=self.client_ip) /
				   TCP(dport=self.server_port, sport=self.client_port, flags="A", seq=self.tcp_sender_seq, ack=reply_seq))
		delayed_sendp(tcp_pkt, self.client_tap)

		server_thread.join(timeout=1)
		assert not server_thread.is_alive(), \
			"Server reply thread is stuck"


	# Helper function to start, send data over, and properly end TCP connection
	def communicate(self):
		self.reset()
		# 3-way handshake
		self.request_tcp("S")
		# data
		self.request_tcp("", payload=_TCPTester.TCP_NORMAL_REQUEST)
		# close connection
		self.request_tcp("F")

	# Helper function to start, send data, and make the server send RST
	def request_rst(self):
		self.reset()
		self.request_tcp("S")
		self.request_tcp("", payload=_TCPTester.TCP_RESET_REQUEST)

	# Helper function to create a dangling connection
	def leave_open(self):
		self.reset()
		self.request_tcp("S")

	# Helper function to simulate a SYN port scan
	def syn_scan(self):
		self.reset()
		self.request_tcp("S", syn_style=_TCPTester.TCP_SYN_SCAN)
		self.request_tcp("S", syn_style=_TCPTester.TCP_SYN_SCAN)

	# Helper function to simulate a SYNACK being retransmitted
	def syn_retrans(self):
		self.reset()
		self.request_tcp("S", syn_style=_TCPTester.TCP_SYN_RETRANSMIT)


class TCPTesterLocal(_TCPTester):
	def __init__(self, client_vm, client_port, server_vm, server_port, client_pkt_check=None, server_pkt_check=None):
		super().__init__(client_vm.tap, client_vm.mac, client_vm.ip, client_port,
						 server_vm.tap, server_vm.mac, server_vm.ip, server_port,
						 client_pkt_check=client_pkt_check, server_pkt_check=server_pkt_check)
	# VM-VM local communication, stay in IPv4
	def get_server_l3_reply(self, pkt):
		return (Ether(dst=pkt[Ether].src, src=pkt[Ether].dst, type=0x0800) /
				IP(dst=pkt[IP].src, src=pkt[IP].dst))

class TCPTesterVirtsvc(_TCPTester):
	def __init__(self, client_vm, client_port, pf_spec, server_ip, server_port, client_pkt_check=None, server_pkt_check=None):
		super().__init__(client_vm.tap, client_vm.mac, client_vm.ip, client_port,
						 pf_spec.tap, pf_spec.mac, server_ip, server_port,
						 client_pkt_check=client_pkt_check, server_pkt_check=server_pkt_check)
	# Virtual-service communication, no tunnel, replace header with IPv6
	def get_server_l3_reply(self, pkt):
		return (Ether(dst=pkt[Ether].src, src=pkt[Ether].dst, type=0x86DD) /
				IPv6(dst=pkt[IPv6].src, src=pkt[IPv6].dst, nh=6))

class TCPTesterPublic(_TCPTester):
	def __init__(self, client_vm, client_port, nat_ul_ipv6, pf_spec, server_ip, server_port, client_pkt_check=None, server_pkt_check=None):
		super().__init__(client_vm.tap, client_vm.mac, client_vm.ip, client_port,
						 pf_spec.tap, pf_spec.mac, server_ip, server_port,
						 client_pkt_check=client_pkt_check, server_pkt_check=server_pkt_check)
		self.nat_ul_ipv6 = nat_ul_ipv6
	# Underlay communication, use IP-IP tunnel
	def get_server_l3_reply(self, pkt):
		return (Ether(dst=pkt[Ether].src, src=pkt[Ether].dst, type=0x86DD) /
				IPv6(dst=self.nat_ul_ipv6, src=pkt[IPv6].dst, nh=4) /
				IP(dst=pkt[IP].src, src=pkt[IP].dst))
