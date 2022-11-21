import threading

from helpers import *


def send_icmp_pkt_from_vm1():

	pkt_list = sniff(count=1, lfilter=is_icmp_pkt, iface=pf0_tap, timeout=10)
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

def test_vf_to_pf_network_nat_icmp(add_machine, request_ip_vf0, grpc_client):

	grpc_client.assert_output(f"--addnat {vm1_name} --ipv4 {nat_vip} --min_port {nat_local_min_port} --max_port {nat_local_max_port}",
		"Received underlay route")

	threading.Thread(target=send_icmp_pkt_from_vm1).start()

	icmp_pkt = (Ether(dst=pf0_mac, src=vf0_mac, type=0x0800) /
			    IP(dst=public_ip, src=vf0_ip) /
			    ICMP(type=8, id=0x0040))
	delayed_sendp(icmp_pkt, vf0_tap)

	pkt_list = sniff(count=1, lfilter=is_icmp_pkt, iface=vf0_tap, timeout=3)
	assert len(pkt_list) == 1, \
		"No ECHO reply"

	pkt = pkt_list[0]
	dst_ip = pkt[IP].dst
	assert dst_ip == vf0_ip, \
		f"Bad ECHO reply (dst ip: {dst_ip})"

	grpc_client.assert_output(f"--delnat {vm1_name}",
		"NAT deleted")


def send_tcp_pkt_from_vm1():

	pkt_list = sniff(count=1, lfilter=is_tcp_pkt, iface=pf0_tap, timeout=10)
	assert len(pkt_list) == 1, \
		"No network-natted TCP packet received on PF"

	pkt = pkt_list[0]
	src_ip = pkt[IP].src
	sport = pkt[TCP].sport
	assert src_ip == nat_vip and sport == nat_local_min_port, \
		f"Bad TCP packet (ip: {src_ip}, sport: {sport})"

	reply_pkt = (Ether(dst=pkt[Ether].src, src=pkt[Ether].dst, type=0x86DD) /
				 IPv6(dst=ul_actual_src, src=pkt[IPv6].dst, nh=4) /
				 IP(dst=pkt[IP].src, src=pkt[IP].dst) /
				 TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport))
	delayed_sendp(reply_pkt, pf0_tap)

def test_vf_to_pf_network_nat_tcp(add_machine, request_ip_vf0, grpc_client):

	# TODO(plague) I suspect that there is an occasional problem here
	# as this test is called immediately after the previous one, that established and then teared down the same route
	# there will be a race condition and the service needs more time this time around
	grpc_client.assert_output(f"--addnat {vm1_name} --ipv4 {nat_vip} --min_port {nat_local_min_port} --max_port {nat_local_max_port}",
		"Received underlay route")

	threading.Thread(target=send_tcp_pkt_from_vm1).start()

	tcp_pkt = (Ether(dst=pf0_mac, src=vf0_mac, type=0x0800) /
			   IP(dst=public_ip, src=vf0_ip) /
			   TCP(sport=1240))
	delayed_sendp(tcp_pkt, vf0_tap)

	pkt_list = sniff(count=1, lfilter=is_tcp_pkt, iface=vf0_tap, timeout=10)
	assert len(pkt_list) == 1, \
		"No network-natted TCP packet received on PF"

	pkt = pkt_list[0]
	dst_ip = pkt[IP].dst
	dport = pkt[TCP].dport
	assert dst_ip == vf0_ip and dport == 1240, \
		f"Bad TCP packet (ip: {dst_ip}, dport: {dport})"

	grpc_client.assert_output(f"--delnat {vm1_name}",
		"NAT deleted")


def encaped_tcp_in_ipv6_vip_responder(pf_name):
	pkt_list = sniff(count=1, lfilter=is_tcp_pkt, iface=pf_name, timeout=10)
	# with --port-redundancy, threre are two listeners running and only one receives a packet
	if len(pkt_list) == 0:
		return
	pkt = pkt_list[0]
	reply_pkt = (Ether(dst=pkt[Ether].src, src=pkt[Ether].dst, type=0x86DD) /
				 IPv6(dst=ul_actual_src, src=pkt[IPv6].dst, nh=4) /
				 IP(dst=pkt[IP].src, src=pkt[IP].dst) /
				 TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport))
	delayed_sendp(reply_pkt, pf_name)

def test_vf_to_pf_vip_snat(add_machine, request_ip_vf0, request_ip_vf1, grpc_client, port_redundancy):

	threading.Thread(target=encaped_tcp_in_ipv6_vip_responder, args=(pf0_tap,)).start()
	if port_redundancy:
		threading.Thread(target=encaped_tcp_in_ipv6_vip_responder, args=(pf1_tap,)).start()

	grpc_client.assert_output(f"--addvip {vm2_name} --ipv4 {virtual_ip}",
		f"Received underlay route : {ul_actual_src}")

	# vm2 (vf1) -> PF0/PF1 (internet traffic), vm2 has VIP, check on PFs side, whether VIP is source (SNAT)
	tcp_pkt = (Ether(dst=pf0_mac, src=vf1_mac, type=0x0800) /
			   IP(dst=public_ip, src=vf1_ip) /
			   TCP(sport=1240))
	delayed_sendp(tcp_pkt, vf1_tap)

	pkt_list = sniff(count=1, lfilter=is_tcp_pkt, iface=vf1_tap, timeout=5)
	assert len(pkt_list) == 1, \
		"No TCP reply via VIP (SNAT)"

	grpc_client.assert_output(f"--delvip {vm2_name}",
		"VIP deleted")
