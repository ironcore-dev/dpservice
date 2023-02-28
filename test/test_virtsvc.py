import threading
import pytest

from helpers import *

TCP_RESET_REQUEST = "Resetme"
TCP_NORMAL_REQUEST = "Hello"
TCP_NORMAL_RESPONSE = "Same to you"

udp_used_port = 0

def reply_udp(pf_name):

	global udp_used_port

	pkt = sniff_packet(pf_name, is_udp_pkt)
	assert pkt[IPv6].dst == virtsvc_udp_svc_ipv6, \
		"Request to wrong IPv6 address"
	assert pkt[UDP].dport == virtsvc_udp_svc_port, \
		"Request to wrong UDP port"
	assert udp_used_port != pkt[UDP].sport, \
		"UDP port reused over multiple connections"

	udp_used_port = pkt[UDP].sport

	reply_pkt = (Ether(dst=pkt[Ether].src, src=pkt[Ether].dst, type=0x86DD) /
				 IPv6(dst=ul_actual_src, src=pkt[IPv6].dst, nh=17) /
				 UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport))
	delayed_sendp(reply_pkt, pf_name)

def request_udp(l4_port, pf_name):

	threading.Thread(target=reply_udp, args=(pf_name,)).start()

	udp_pkt = (Ether(dst=pf0_mac, src=vf0_mac, type=0x0800) /
			   IP(dst=virtsvc_udp_virtual_ip, src=vf0_ip) /
			   UDP(dport=virtsvc_udp_virtual_port, sport=l4_port))
	delayed_sendp(udp_pkt, vf0_tap)

	pkt = sniff_packet(vf0_tap, is_udp_pkt)
	assert pkt[IP].src == virtsvc_udp_virtual_ip, \
		"Got answer from wrong UDP source port"
	assert pkt[UDP].sport == virtsvc_udp_virtual_port, \
		"Got answer from wrong UDP source port"
	assert pkt[UDP].dport == l4_port, \
		"Got answer to wrong UDP destination port"


# TCP state machine
tcp_sender_seq = 100
tcp_receiver_seq = 200
tcp_used_port = 0

def tcp_reset():
	global tcp_sender_seq
	global tcp_receiver_seq
	global tcp_used_port
	tcp_sender_seq = 100
	tcp_receiver_seq = 200
	tcp_used_port = 0

def get_server_packet(pf_name):
	global tcp_used_port
	pkt = sniff_packet(pf_name, is_tcp_pkt)
	assert pkt[IPv6].dst == virtsvc_tcp_svc_ipv6, \
		"Request to wrong IPv6 address"
	assert pkt[TCP].dport == virtsvc_tcp_svc_port, \
		"Request to wrong TCP port"
	assert tcp_used_port == 0 or pkt[TCP].sport == tcp_used_port, \
		"Server port changed during communication"
	tcp_used_port = pkt[TCP].sport
	return pkt

def reply_tcp(pf_name):

	global tcp_receiver_seq

	pkt = get_server_packet(pf_name)

	# Received ACK only, just end
	if pkt[TCP].flags == "A":
		return

	# Communication in this test is always client-initiated, always ACK
	flags = "A"

	# SYN request needs SYNACK
	if pkt[TCP].flags == "S":
		flags += "S"

	reply_pkt = (Ether(dst=pkt[Ether].src, src=pkt[Ether].dst, type=0x86DD) /
				 IPv6(dst=ul_actual_src, src=pkt[IPv6].dst, nh=6) /
				 TCP(dport=pkt[TCP].sport, sport=pkt[TCP].dport, seq=tcp_receiver_seq, flags=flags, ack=pkt[TCP].seq+1, options=[("NOP", None)]))
	delayed_sendp(reply_pkt, pf_name)

	if flags != "A":
		tcp_receiver_seq += 1

	# FIN -> ACK+FINACK (ACK done above already)
	if "F" in pkt[TCP].flags:
		reply_pkt = (Ether(dst=pkt[Ether].src, src=pkt[Ether].dst, type=0x86DD) /
					 IPv6(dst=ul_actual_src, src=pkt[IPv6].dst, nh=6) /
					 TCP(dport=pkt[TCP].sport, sport=pkt[TCP].dport, seq=tcp_receiver_seq, flags="FA", ack=pkt[TCP].seq+1))
		delayed_sendp(reply_pkt, pf_name)
		return

	# Application-level reply
	if pkt[TCP].payload != None and len(pkt[TCP].payload) > 0:
		if pkt[TCP].payload == Raw(TCP_RESET_REQUEST):
			reply_pkt = (Ether(dst=pkt[Ether].src, src=pkt[Ether].dst, type=0x86DD) /
						 IPv6(dst=ul_actual_src, src=pkt[IPv6].dst, nh=6) /
						 TCP(dport=pkt[TCP].sport, sport=pkt[TCP].dport, seq=tcp_receiver_seq, flags="R"))
			delayed_sendp(reply_pkt, pf_name)
			return

		reply_pkt = (Ether(dst=pkt[Ether].src, src=pkt[Ether].dst, type=0x86DD) /
					 IPv6(dst=ul_actual_src, src=pkt[IPv6].dst, nh=6) /
					 TCP(dport=pkt[TCP].sport, sport=pkt[TCP].dport, seq=tcp_receiver_seq, flags="") /
					 Raw(TCP_NORMAL_RESPONSE))
		delayed_sendp(reply_pkt, pf_name)
		tcp_receiver_seq += len(TCP_NORMAL_RESPONSE)

	# Await ACK
	pkt = get_server_packet(pf_name)
	assert pkt[TCP].flags == "A", \
		"Expected an ACK packet"

def get_client_packet(port):
	pkt = sniff_packet(vf0_tap, is_tcp_pkt)
	assert pkt[IP].src == virtsvc_tcp_virtual_ip, \
		"Got answer from wrong TCP source port"
	assert pkt[TCP].sport == virtsvc_tcp_virtual_port, \
		"Got answer from wrong TCP source port"
	assert pkt[TCP].dport == port, \
		"Got answer to wrong TCP destination port"
	return pkt

def request_tcp(l4_port, flags, pf_name, payload=None):

	global tcp_sender_seq

	threading.Thread(target=reply_tcp, args=(pf_name,)).start()

	tcp_pkt = (Ether(dst=pf0_mac, src=vf0_mac, type=0x0800) /
			   IP(dst=virtsvc_tcp_virtual_ip, src=vf0_ip) /
			   TCP(dport=virtsvc_tcp_virtual_port, sport=l4_port, seq=tcp_sender_seq, flags=flags, options=[("NOP", None)]))
	if payload != None:
		tcp_pkt /= Raw(payload)
	delayed_sendp(tcp_pkt, vf0_tap)

	# No reaction to ACK
	if flags == "A":
		return

	# React to the packet
	tcp_sender_seq += 1 if payload is None else len(payload)

	pkt = get_client_packet(l4_port)
	reply_seq = pkt.seq;

	assert "A" in pkt[TCP].flags, \
		"No ACK from server"

	# FIN_WAIT
	if "F" in flags:
		pkt = get_client_packet(l4_port)
		assert pkt[TCP].flags == "FA", \
			"No FINACK from server"

	# When sending payload, ACK is first, then separate reply
	if payload is None:
		reply_seq += 1
	else:
		pkt = get_client_packet(l4_port)
		if "R" in pkt[TCP].flags:
			assert payload is not None and payload == TCP_RESET_REQUEST, \
				"Unexpected connection reset"
			tcp_reset()
			return
		else:
			assert pkt[TCP].payload == Raw(TCP_NORMAL_RESPONSE), \
				"Bad answer from virtual service"
		reply_seq += len(payload)

	# send ACK
	tcp_pkt = (Ether(dst=pf0_mac, src=vf0_mac, type=0x0800) /
			   IP(dst=virtsvc_tcp_virtual_ip, src=vf0_ip) /
			   TCP(dport=virtsvc_tcp_virtual_port, sport=l4_port, flags="A", ack=reply_seq))
	delayed_sendp(tcp_pkt, vf0_tap)

def communicate_tcp(port, pf_name):
	tcp_reset()
	# 3-way handshake
	request_tcp(port, "S", pf_name)
	# data
	request_tcp(port, "", pf_name, payload=TCP_NORMAL_REQUEST)
	# close connection
	request_tcp(port, "F", pf_name)


def test_virtsvc_udp(request, prepare_ipv4, port_redundancy):
	if not request.config.getoption("--virtsvc"):
		pytest.skip("Virtual services not enabled")
	# port numbers chosen so that they cause the right redirection
	for port in [ 12345, 12346, 12348, 12349, 12350 ]:
		request_udp(port, pf0_tap)
	if port_redundancy:
		for port in [ 12347, 12351, 12354, 12355, 12356 ]:
			request_udp(port, pf1_tap)

def test_virtsvc_tcp(request, prepare_ipv4, port_redundancy):
	if not request.config.getoption("--virtsvc"):
		pytest.skip("Virtual services not enabled")
	# port numbers chosen so that they cause the right redirection
	communicate_tcp(12345, pf0_tap)
	if port_redundancy:
		communicate_tcp(54321, pf1_tap)


# This is a test for debugging TCP RST in virtual service implementation
# Without crafted debug setup of the code, this cannot be tested automatically
def disabled_test_virtsvc_tcp_reset(request, prepare_ipv4, port_redundancy):
	if not request.config.getoption("--virtsvc"):
		pytest.skip("Virtual services not enabled")
	tcp_port = 43210
	# tcp_reset()
	request_tcp(tcp_port, "S", pf0_tap)
	request_tcp(tcp_port, "", pf0_tap, payload=TCP_RESET_REQUEST)
