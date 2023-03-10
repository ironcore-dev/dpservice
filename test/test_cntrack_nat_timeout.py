import threading
import pytest

from helpers import *

TCP_RESET_REQUEST = "Resetme"
TCP_NORMAL_REQUEST = "Hello"
TCP_NORMAL_RESPONSE = "Same to you"


# TCP state machine
tcp_sender_seq = 100
tcp_receiver_seq = 200
tcp_used_port = 0
nat_ipv6_src = ""

def tcp_reset():
	global tcp_sender_seq
	global tcp_receiver_seq
	global tcp_used_port
	tcp_sender_seq = 100
	tcp_receiver_seq = 200
	tcp_used_port = 0

def get_server_packet(pf_name):
	global tcp_used_port
	global nat_ipv6_src

	pkt = sniff_packet(pf_name, is_tcp_pkt)

	assert pkt[IPv6].dst == ul_actual_dst, \
		"Request to the wrong outgoing IPv6 address"
	assert pkt[IP].src == nat_vip, \
		f"Bad TCP pkt, not the NAT's IP (src ip: {src_ip})"
	assert pkt[IP].dst == public_server_ip, \
		"Request to the wrong public server IP"
	assert pkt[TCP].dport == public_server_port, \
		"Request to wrong TCP port"
	assert pkt[TCP].sport == nat_local_single_min_port, \
		"Failed to use NAT's only single port"
	assert tcp_used_port == 0 or pkt[TCP].sport == tcp_used_port, \
		"Server port changed during communication"
	tcp_used_port = pkt[TCP].sport
	return pkt

def reply_tcp(pf_name):

	global tcp_receiver_seq
	global nat_ipv6_src

	pkt = get_server_packet(pf_name)

	# Received ACK only, just end
	if pkt[TCP].flags == "A":
		return

	# Communication in this test is always client-initiated, always ACK
	flags = "A"

	# SYN request needs SYNACK
	if pkt[TCP].flags == "S":
		flags += "S"

	# FIN -> FINACK (ACK done above already)
	if "F" in pkt[TCP].flags:
		reply_pkt = (Ether(dst=pkt[Ether].src, src=pkt[Ether].dst, type=0x86DD) /
					 IPv6(dst=nat_ipv6_src, src=pkt[IPv6].dst, nh=4) /
					 IP(dst=pkt[IP].src, src=pkt[IP].dst) /
					 TCP(dport=pkt[TCP].sport, sport=pkt[TCP].dport, seq=tcp_receiver_seq, flags="FA", ack=pkt[TCP].seq+1))
		delayed_sendp(reply_pkt, pf_name)
		# Await ACK
		pkt = get_server_packet(pf_name)
		assert pkt[TCP].flags == "A", \
			"Expected an final ACK for fin packet"
		return


	reply_pkt = (Ether(dst=pkt[Ether].src, src=pkt[Ether].dst, type=0x86DD) /
				 IPv6(dst=nat_ipv6_src, src=pkt[IPv6].dst, nh=4) /
				 IP(dst=pkt[IP].src, src=pkt[IP].dst) /
				 TCP(dport=pkt[TCP].sport, sport=pkt[TCP].dport, seq=tcp_receiver_seq, flags=flags, ack=pkt[TCP].seq+1, options=[("NOP", None)]))
	time.sleep(0.5)
	delayed_sendp(reply_pkt, pf_name)


	if flags != "A":
		tcp_receiver_seq += 1


	# Application-level reply
	if pkt[TCP].payload != None and len(pkt[TCP].payload) > 0:
		if pkt[TCP].payload == Raw(TCP_RESET_REQUEST):
			reply_pkt = (Ether(dst=pkt[Ether].src, src=pkt[Ether].dst, type=0x86DD) /
						 IPv6(dst=nat_ipv6_src, src=pkt[IPv6].dst, nh=4) /
						 IP(dst=pkt[IP].src, src=pkt[IP].dst) /
						 TCP(dport=pkt[TCP].sport, sport=pkt[TCP].dport, seq=tcp_receiver_seq, flags="R"))
			delayed_sendp(reply_pkt, pf_name)
			return

		reply_pkt = (Ether(dst=pkt[Ether].src, src=pkt[Ether].dst, type=0x86DD) /
					 IPv6(dst=nat_ipv6_src, src=pkt[IPv6].dst, nh=4) /
					 IP(dst=pkt[IP].src, src=pkt[IP].dst) /
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
	assert pkt[IP].src == public_server_ip, \
		"Got answer from wrong TCP source ip of the public server"
	assert pkt[TCP].sport == public_server_port, \
		"Got answer from wrong TCP source port of the public server"
	assert pkt[IP].dst == vf0_ip, \
		"Got answer destinated for the wrong VM IP"
	assert pkt[TCP].dport == port, \
		"Got answer destinated for the wrong VM port"
	return pkt

def request_tcp(l4_port, flags, pf_name, payload=None):

	global tcp_sender_seq

	threading.Thread(target=reply_tcp, args=(pf_name,)).start()

	tcp_pkt = (Ether(dst=pf0_mac, src=vf0_mac, type=0x0800) /
			   IP(dst=public_server_ip, src=vf0_ip) /
			   TCP(dport=public_server_port, sport=l4_port, seq=tcp_sender_seq, flags=flags, options=[("NOP", None)]))
	if payload != None:
		tcp_pkt /= Raw(payload)
	delayed_sendp(tcp_pkt, vf0_tap)


	# No reaction to ACK
	if flags == "A":
		return

	# React to the packet
	tcp_sender_seq += 1 if payload is None else len(payload)

	# check server's FINACK
	if "FA" in flags:
		pkt = get_client_packet(l4_port)
		assert pkt[TCP].flags == "FA", \
			"No FINACK from server"
		reply_seq = pkt.seq;
		
		# send ACK
		tcp_pkt = (Ether(dst=pf0_mac, src=vf0_mac, type=0x0800) /
			   IP(dst=public_server_ip, src=vf0_ip) /
			   TCP(dport=public_server_port, sport=l4_port, flags="A", ack=reply_seq))
		delayed_sendp(tcp_pkt, vf0_tap)
		return


	pkt = get_client_packet(l4_port)
	reply_seq = pkt.seq;

	assert "A" in pkt[TCP].flags, \
		"No ACK from server"

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
			   IP(dst=public_server_ip, src=vf0_ip) /
			   TCP(dport=public_server_port, sport=l4_port, flags="A", ack=reply_seq))
	delayed_sendp(tcp_pkt, vf0_tap)

def communicate_tcp(port, pf_name):
	tcp_reset()
	# 3-way handshake
	request_tcp(port, "S", pf_name)
	request_tcp(port, "", pf_name, payload=TCP_NORMAL_REQUEST)
	# close connection
	request_tcp(port, "FA", pf_name)

def test_cntrack_nat_timeout_tcp(request, prepare_ipv4, grpc_client):
	global nat_ipv6_src

	nat_ipv6_src = grpc_client.addnat(vm1_name, nat_vip, nat_local_single_min_port, nat_local_single_max_port)

	communicate_tcp(12345, pf0_tap)
	time.sleep(10) #after 10 seconds, the assigned port and corresponding flow rule shall be released and deleted
	communicate_tcp(54321, pf0_tap)

	grpc_client.delnat(vm1_name)


