import pytest
import threading

from helpers import *


def reply_icmp_pkt_from_vm1():

	pkt_list = sniff(count=1, lfilter=is_icmp_pkt, iface=pf0_tap, timeout=2)
	assert len(pkt_list) == 1, \
		"No network-natted ICMP packet received on PF"

	pkt = pkt_list[0]
	src_ip = pkt[IP].src
	assert src_ip == nat_vip, \
		f"Bad ICMP request (src ip: {src_ip})"

	reply_pkt = (Ether(dst=pkt[Ether].src, src=pkt[Ether].dst, type=0x86DD) /
				 IPv6(dst=ul_actual_src, src=pkt[IPv6].dst, nh=4) /
				 IP(dst=pkt[IP].src, src=pkt[IP].dst) /
				 ICMP(type=0, id=pkt[ICMP].id))
	delayed_sendp(reply_pkt, pf0_tap)

def test_vf_to_pf_network_nat_icmp(prepare_ipv4, grpc_client):

	grpc_client.assert_output(f"--addnat {vm1_name} --ipv4 {nat_vip} --min_port {nat_local_min_port} --max_port {nat_local_max_port}",
		"Received underlay route")

	threading.Thread(target=reply_icmp_pkt_from_vm1).start()

	icmp_pkt = (Ether(dst=pf0_mac, src=vf0_mac, type=0x0800) /
			    IP(dst=public_ip, src=vf0_ip) /
			    ICMP(type=8, id=0x0040))
	delayed_sendp(icmp_pkt, vf0_tap)

	pkt_list = sniff(count=1, lfilter=is_icmp_pkt, iface=vf0_tap, timeout=2)
	assert len(pkt_list) == 1, \
		"No ECHO reply"

	pkt = pkt_list[0]
	dst_ip = pkt[IP].dst
	assert dst_ip == vf0_ip, \
		f"Bad ECHO reply (dst ip: {dst_ip})"

	grpc_client.assert_output(f"--delnat {vm1_name}",
		"NAT deleted")


def reply_tcp_if_port_not(forbidden_port):

	pkt_list = sniff(count=1, lfilter=is_tcp_pkt, iface=pf0_tap, timeout=2)
	assert len(pkt_list) == 1, \
		"No network-natted TCP packet received on PF"

	pkt = pkt_list[0]
	src_ip = pkt[IP].src
	sport = pkt[TCP].sport
	assert src_ip == nat_vip and sport >= nat_local_min_port and sport < nat_local_max_port, \
		f"Bad TCP packet (ip: {src_ip}, sport: {sport})"

	if forbidden_port is None or sport != forbidden_port:
		reply_pkt = (Ether(dst=pkt[Ether].src, src=pkt[Ether].dst, type=0x86DD) /
					 IPv6(dst=ul_actual_src, src=pkt[IPv6].dst, nh=4) /
					 IP(dst=pkt[IP].src, src=pkt[IP].dst) /
					 TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport))
		delayed_sendp(reply_pkt, pf0_tap)

	return sport

def reply_tcp_pkt_from_vm1():
	reply_tcp_if_port_not(None)

def reply_tcp_pkt_from_vm1_max_port():
	sport = reply_tcp_if_port_not(None)
	reply_tcp_if_port_not(sport)

def send_tcp_through_port(port):

	tcp_pkt = (Ether(dst=pf0_mac, src=vf0_mac, type=0x0800) /
			   IP(dst=public_ip, src=vf0_ip) /
			   TCP(sport=port))
	delayed_sendp(tcp_pkt, vf0_tap)

	pkt_list = sniff(count=1, lfilter=is_tcp_pkt, iface=vf0_tap, timeout=2)
	assert len(pkt_list) == 1, \
		"No network-natted TCP packet received on VF"

	pkt = pkt_list[0]
	dst_ip = pkt[IP].dst
	dport = pkt[TCP].dport
	assert dst_ip == vf0_ip and dport == port, \
		f"Bad TCP packet (ip: {dst_ip}, dport: {dport})"


def test_vf_to_pf_network_nat_max_port_tcp(prepare_ipv4, grpc_client, port_redundancy):

	if port_redundancy:
		pytest.skip("Port redundancy is not supported for NAT max port test")

	grpc_client.assert_output(f"--addnat {vm1_name} --ipv4 {nat_vip} --min_port {nat_local_min_port} --max_port {nat_local_max_port}",
		"Received underlay route")

	threading.Thread(target=reply_tcp_pkt_from_vm1_max_port).start()
	send_tcp_through_port(1240)
	send_tcp_through_port(1241)

	grpc_client.assert_output(f"--delnat {vm1_name}",
		"NAT deleted")


def test_vf_to_pf_network_nat_tcp(prepare_ipv4, grpc_client):

	grpc_client.assert_output(f"--addnat {vm1_name} --ipv4 {nat_vip} --min_port {nat_local_min_port} --max_port {nat_local_max_port}",
		"Received underlay route")

	threading.Thread(target=reply_tcp_pkt_from_vm1).start()
	send_tcp_through_port(1240)

	grpc_client.assert_output(f"--delnat {vm1_name}",
		"NAT deleted")


def encaped_tcp_in_ipv6_vip_responder(pf_name):
	pkt_list = sniff(count=1, lfilter=is_tcp_pkt, iface=pf_name, timeout=2)
	assert len(pkt_list) == 1, \
		"No VIP TCP packet received on PF"
	pkt = pkt_list[0]
	reply_pkt = (Ether(dst=pkt[Ether].src, src=pkt[Ether].dst, type=0x86DD) /
				 IPv6(dst=ul_actual_src, src=pkt[IPv6].dst, nh=4) /
				 IP(dst=pkt[IP].src, src=pkt[IP].dst) /
				 TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport))
	delayed_sendp(reply_pkt, pf_name)

def request_tcp(dport, pf_name):

	threading.Thread(target=encaped_tcp_in_ipv6_vip_responder, args=(pf_name,)).start()

	# vm2 (vf1) -> PF0/PF1 (internet traffic), vm2 has VIP, check on PFs side, whether VIP is source (SNAT)
	tcp_pkt = (Ether(dst=pf0_mac, src=vf1_mac, type=0x0800) /
			   IP(dst=public_ip, src=vf1_ip) /
			   TCP(sport=1240, dport=dport))
	delayed_sendp(tcp_pkt, vf1_tap)

	pkt_list = sniff(count=1, lfilter=is_tcp_pkt, iface=vf1_tap, timeout=2)
	assert len(pkt_list) == 1, \
		"No TCP reply via VIP (SNAT)"

def test_vf_to_pf_vip_snat(prepare_ipv4, grpc_client, port_redundancy):

	grpc_client.assert_output(f"--addvip {vm2_name} --ipv4 {virtual_ip}",
		f"Received underlay route : {ul_actual_src}")

	request_tcp(80, pf0_tap)
	if port_redundancy:
		request_tcp(81, pf1_tap)

	grpc_client.assert_output(f"--delvip {vm2_name}",
		"VIP deleted")


def reply_with_icmp_err_fragment_needed(pf_name):
	pkt_list = sniff(count=1, lfilter=is_tcp_pkt, iface=pf_name, timeout=2)
	assert len(pkt_list) == 1, \
		"No network-natted TCP packet received on PF"
	pkt = pkt_list[0]
	orig_ip_pkt = pkt[IP]
	reply_pkt = (Ether(dst=pkt[Ether].src, src=pkt[Ether].dst, type=0x86DD) /
				 IPv6(dst=ul_actual_src, src=pkt[IPv6].dst, nh=4) /
				 IP(dst=orig_ip_pkt.src, src=orig_ip_pkt.dst) /
				 ICMP(type=3, code=4, unused=1280) /
				 orig_ip_pkt)
	# https://blog.cloudflare.com/path-mtu-discovery-in-practice/
	"""
	reply_pkt = (Ether(dst=pkt[Ether].src, src=pkt[Ether].dst, type=0x86DD) /
				 IPv6(dst=ul_actual_src, src=pkt[IPv6].dst, nh=4) /
				 IP(dst=orig_ip_pkt.src, src=orig_ip_pkt.dst) /
				 ICMP(type=3, code=4, unused=1280) /
				 str(orig_ip_pkt)[:28])
	"""
	delayed_sendp(reply_pkt, pf_name)

def request_icmperr(dport, pf_name):

	threading.Thread(target=reply_with_icmp_err_fragment_needed, args=(pf_name,)).start();

	tcp_pkt = (Ether(dst=mc_mac, src=vf0_mac, type=0x0800) /
			   IP(dst=public_ip, src=vf0_ip) /
			   TCP(sport=1256, dport=dport))
	delayed_sendp(tcp_pkt, vf0_tap)

	pkt_list = sniff(count=1, lfilter=is_icmp_pkt, iface=vf0_tap, timeout=5)
	assert len(pkt_list) == 1, \
		"Cannot receive asymmetric ICMP packet on VF"

	pkt = pkt_list[0]
	icmp_type = pkt[ICMP].type
	assert icmp_type == 3, \
		f"Received wrong icmp packet type: {icmp_type}"

def test_vm_nat_async_tcp_icmperr(prepare_ipv4, grpc_client, port_redundancy):

	grpc_client.assert_output(f"--addnat {vm1_name} --ipv4 {nat_vip} --min_port {nat_local_min_port} --max_port {nat_local_max_port}",
		"Received underlay route")

	request_icmperr(502, pf0_tap)
	if port_redundancy:
		request_icmperr(501, pf1_tap)

	grpc_client.assert_output(f"--delnat {vm1_name}",
		"NAT deleted")
