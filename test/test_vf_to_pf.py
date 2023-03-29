import pytest
import threading

from helpers import *


def reply_icmp_pkt_from_vm1(nat_ul_ipv6):

	pkt = sniff_packet(PF0.tap, is_icmp_pkt)
	src_ip = pkt[IP].src
	assert src_ip == nat_vip, \
		f"Bad ICMP request (src ip: {src_ip})"

	reply_pkt = (Ether(dst=pkt[Ether].src, src=pkt[Ether].dst, type=0x86DD) /
				 IPv6(dst=nat_ul_ipv6, src=pkt[IPv6].dst, nh=4) /
				 IP(dst=pkt[IP].src, src=pkt[IP].dst) /
				 ICMP(type=0, id=pkt[ICMP].id))
	delayed_sendp(reply_pkt, PF0.tap)

def xtest_vf_to_pf_network_nat_icmp(prepare_ipv4, grpc_client):

	nat_ul_ipv6 = grpc_client.addnat(VM1.name, nat_vip, nat_local_min_port, nat_local_max_port)

	threading.Thread(target=reply_icmp_pkt_from_vm1, args=(nat_ul_ipv6,)).start()

	icmp_pkt = (Ether(dst=PF0.mac, src=VM1.mac, type=0x0800) /
			    IP(dst=public_ip, src=VM1.ip) /
			    ICMP(type=8, id=0x0040))
	delayed_sendp(icmp_pkt, VM1.tap)

	pkt = sniff_packet(VM1.tap, is_icmp_pkt)
	dst_ip = pkt[IP].dst
	assert dst_ip == VM1.ip, \
		f"Bad ECHO reply (dst ip: {dst_ip})"

	grpc_client.delnat(VM1.name)


def reply_tcp_if_port_not(forbidden_port, nat_ul_ipv6):

	pkt = sniff_packet(PF0.tap, is_tcp_pkt)
	src_ip = pkt[IP].src
	sport = pkt[TCP].sport
	assert src_ip == nat_vip and sport >= nat_local_min_port and sport < nat_local_max_port, \
		f"Bad TCP packet (ip: {src_ip}, sport: {sport})"

	if forbidden_port is None or sport != forbidden_port:
		reply_pkt = (Ether(dst=pkt[Ether].src, src=pkt[Ether].dst, type=0x86DD) /
					 IPv6(dst=nat_ul_ipv6, src=pkt[IPv6].dst, nh=4) /
					 IP(dst=pkt[IP].src, src=pkt[IP].dst) /
					 TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport))
		delayed_sendp(reply_pkt, PF0.tap)

	return sport

def reply_tcp_pkt_from_vm1(nat_ul_ipv6):
	reply_tcp_if_port_not(None, nat_ul_ipv6)

def reply_tcp_pkt_from_vm1_max_port(nat_ul_ipv6):
	sport = reply_tcp_if_port_not(None, nat_ul_ipv6)
	reply_tcp_if_port_not(sport, nat_ul_ipv6)

def send_tcp_through_port(port):

	tcp_pkt = (Ether(dst=PF0.mac, src=VM1.mac, type=0x0800) /
			   IP(dst=public_ip, src=VM1.ip) /
			   TCP(sport=port))
	delayed_sendp(tcp_pkt, VM1.tap)

	pkt = sniff_packet(VM1.tap, is_tcp_pkt)
	dst_ip = pkt[IP].dst
	dport = pkt[TCP].dport
	assert dst_ip == VM1.ip and dport == port, \
		f"Bad TCP packet (ip: {dst_ip}, dport: {dport})"


def test_vf_to_pf_network_nat_max_port_tcp(prepare_ipv4, grpc_client, port_redundancy):
	nat_ul_ipv6 = grpc_client.addnat(VM1.name, nat_vip, nat_local_min_port, nat_local_max_port)
	threading.Thread(target=reply_tcp_pkt_from_vm1_max_port, args=(nat_ul_ipv6,)).start()
	send_tcp_through_port(1242)
	send_tcp_through_port(1243)
	grpc_client.delnat(VM1.name)


def test_vf_to_pf_network_nat_tcp(prepare_ipv4, grpc_client):
	nat_ul_ipv6 = grpc_client.addnat(VM1.name, nat_vip, nat_local_min_port, nat_local_max_port)
	threading.Thread(target=reply_tcp_pkt_from_vm1, args=(nat_ul_ipv6,)).start()
	send_tcp_through_port(1242)
	grpc_client.delnat(VM1.name)


def encaped_tcp_in_ipv6_vip_responder(pf_name, vip_ul_ipv6):
	pkt = sniff_packet(pf_name, is_tcp_pkt)
	reply_pkt = (Ether(dst=pkt[Ether].src, src=pkt[Ether].dst, type=0x86DD) /
				 IPv6(dst=vip_ul_ipv6, src=pkt[IPv6].dst, nh=4) /
				 IP(dst=pkt[IP].src, src=pkt[IP].dst) /
				 TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport))
	delayed_sendp(reply_pkt, pf_name)

def request_tcp(dport, pf_name, vip_ul_ipv6):
	threading.Thread(target=encaped_tcp_in_ipv6_vip_responder, args=(pf_name, vip_ul_ipv6)).start()
	# vm2 (vf1) -> PF0/PF1 (internet traffic), vm2 has VIP, check on PFs side, whether VIP is source (SNAT)
	tcp_pkt = (Ether(dst=PF0.mac, src=VM2.mac, type=0x0800) /
			   IP(dst=public_ip, src=VM2.ip) /
			   TCP(sport=1240, dport=dport))
	delayed_sendp(tcp_pkt, VM2.tap)
	sniff_packet(VM2.tap, is_tcp_pkt)

def test_vf_to_pf_vip_snat(prepare_ipv4, grpc_client, port_redundancy):
	vip_ul_ipv6 = grpc_client.addvip(VM2.name, vip_vip)
	request_tcp(80, PF0.tap, vip_ul_ipv6)
	if port_redundancy:
		request_tcp(82, PF1.tap, vip_ul_ipv6)
	grpc_client.delvip(VM2.name)


def reply_with_icmp_err_fragment_needed(pf_name, nat_ul_ipv6):
	pkt = sniff_packet(pf_name, is_tcp_pkt)
	orig_ip_pkt = pkt[IP]
	reply_pkt = (Ether(dst=pkt[Ether].src, src=pkt[Ether].dst, type=0x86DD) /
				 IPv6(dst=nat_ul_ipv6, src=pkt[IPv6].dst, nh=4) /
				 IP(dst=orig_ip_pkt.src, src=orig_ip_pkt.dst) /
				 ICMP(type=3, code=4, unused=1280) /
				 orig_ip_pkt)
	# https://blog.cloudflare.com/path-mtu-discovery-in-practice/
	"""
	reply_pkt = (Ether(dst=pkt[Ether].src, src=pkt[Ether].dst, type=0x86DD) /
				 IPv6(dst=nat_ul_ipv6, src=pkt[IPv6].dst, nh=4) /
				 IP(dst=orig_ip_pkt.src, src=orig_ip_pkt.dst) /
				 ICMP(type=3, code=4, unused=1280) /
				 str(orig_ip_pkt)[:28])
	"""
	delayed_sendp(reply_pkt, pf_name)

def request_icmperr(dport, pf_name, nat_ul_ipv6):

	threading.Thread(target=reply_with_icmp_err_fragment_needed, args=(pf_name, nat_ul_ipv6)).start();

	tcp_pkt = (Ether(dst=ipv6_multicast_mac, src=VM1.mac, type=0x0800) /
			   IP(dst=public_ip, src=VM1.ip) /
			   TCP(sport=1256, dport=dport))
	delayed_sendp(tcp_pkt, VM1.tap)

	pkt = sniff_packet(VM1.tap, is_icmp_pkt)
	icmp_type = pkt[ICMP].type
	assert icmp_type == 3, \
		f"Received wrong icmp packet type: {icmp_type}"

def test_vm_nat_async_tcp_icmperr(prepare_ipv4, grpc_client, port_redundancy):
	nat_ul_ipv6 = grpc_client.addnat(VM1.name, nat_vip, nat_local_min_port, nat_local_max_port)
	request_icmperr(506, PF0.tap, nat_ul_ipv6)
	if port_redundancy:
		request_icmperr(500, PF1.tap, nat_ul_ipv6)
	grpc_client.delnat(VM1.name)

def test_vf_to_pf_firewall_tcp(prepare_ipv4, grpc_client):
	sniff_tcp_data = {}
	negated=True
	resp_thread = threading.Thread(target=sniff_tcp_fwall_packet, args=(PF0.tap, sniff_tcp_data, negated))
	resp_thread.start()
	#Allow only tcp packets to leave the VM with destination port 453
	grpc_client.addfwallrule(VM1.name, "fw0-vm1", 0, 0, "0.0.0.0", 0, -1, -1, 453, 453, "tcp", "accept", "egress")
	tcp_pkt = (Ether(dst=PF0.mac, src=VM1.mac, type=0x0800) /
			   IP(dst=public_ip, src=VM1.ip) /
			   TCP(dport=1024))
	delayed_sendp(tcp_pkt, VM1.tap)

	resp_thread.join()
	#It should not arrive at the PF0, as firewall filters it
	assert sniff_tcp_data["pkt"] == None
	grpc_client.delfwallrule(VM1.name, "fw0-vm1")

def test2_vf_to_pf_firewall_tcp(prepare_ipv4, grpc_client, port_redundancy):
	if port_redundancy:
		pytest.skip()
	sniff_tcp_data = {}
	resp_thread = threading.Thread(target=sniff_tcp_fwall_packet, args=(PF0.tap, sniff_tcp_data,))
	resp_thread.start()
	#Allow only tcp packets to leave the VM with destination port 453
	grpc_client.addfwallrule(VM1.name, "fw1-vm1", 0, 0, "0.0.0.0", 0, -1, -1, 453, 453, "tcp", "accept", "egress")
	tcp_pkt = (Ether(dst=PF0.mac, src=VM1.mac, type=0x0800) /
			   IP(dst=public_ip, src=VM1.ip) /
			   TCP(dport=453))
	delayed_sendp(tcp_pkt, VM1.tap)

	resp_thread.join()
	#It should arrive at the PF0 or PF1, as firewall allows it
	assert sniff_tcp_data["pkt"] != None
	grpc_client.delfwallrule(VM1.name, "fw1-vm1")
