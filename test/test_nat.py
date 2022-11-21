import threading

from helpers import *


def test_network_nat_external_icmp_echo(add_machine, request_ip_vf0, grpc_client):

	grpc_client.assert_output(f"--addnat {vm1_name} --ipv4 {nat_vip} --min_port {nat_local_min_port} --max_port {nat_local_max_port}",
		"Received underlay route")

	icmp_pkt = (Ether(dst=mc_mac, src=pf0_mac, type=0x86DD) /
			    IPv6(dst=ul_actual_dst, src=ul_actual_src, nh=4) /
			    IP(dst=nat_vip, src=public_ip) /
			    ICMP(type=8, id=0x0040))
	answer = srp1(icmp_pkt, iface=pf0_tap, timeout=2)
	assert answer and is_icmp_pkt(answer)

	grpc_client.assert_output(f"--delnat {vm1_name}",
		"NAT deleted")


def send_bounce_pkt_to_pf():
	bouce_pkt = (Ether(dst=mc_mac, src=pf0_mac, type=0x86DD) /
				 IPv6(dst=ul_actual_dst, src=ul_actual_src, nh=4) /
				 IP(dst=nat_vip, src=public_ip) /
				 TCP(sport=8989, dport=510))
	time.sleep(3)
	sendp(bouce_pkt, iface=pf0_tap)

def test_network_nat_pkt_relay(add_machine, grpc_client):

	grpc_client.assert_output(f"--addnat {vm1_name} --ipv4 {nat_vip} --min_port {nat_local_min_port} --max_port {nat_local_max_port}",
		"Received underlay route")

	grpc_client.assert_output(f"--addneighnat --ipv4 {nat_vip} --vni {vni} --min_port {nat_neigh_min_port} --max_port {nat_neigh_max_port} --t_ipv6 {nat_neigh_ul_dst}",
		"Neighbor NAT added")

	threading.Thread(target=send_bounce_pkt_to_pf).start();

	# answer, unanswered = srp(bouce_pkt, iface=pf0_tap, timeout=10)
	pkt_list = sniff(count=2, lfilter=is_tcp_pkt, iface=pf0_tap, timeout=10)
	assert len(pkt_list) == 2

	# it seems that pkt_list[0] is the injected pkt
	pkt = pkt_list[1]

	if Ether in pkt:
		pktether = pkt[Ether]
	if IPv6 in pkt:
		pktipv6 = pkt[IPv6]
	if IP in pkt:
		pktip = pkt[IP]
	if TCP in pkt:
		pkttcp = pkt[TCP]
	assert pktipv6.dst == nat_neigh_ul_dst and pkttcp.dport == 510, 'Received wrong network-nat relayed packet with outer dst ipv6 addr:'+pktipv6.dst+" dport:"+pkttcp.dport

	grpc_client.assert_output(f"--getnat {vm1_name}",
		nat_vip)

	grpc_client.assert_output(f"--getnatinfo neigh --ipv4 {nat_vip}",
		nat_neigh_ul_dst)

	grpc_client.assert_output(f"--delneighnat --ipv4 {nat_vip} --vni {vni} --min_port {nat_neigh_min_port} --max_port {nat_neigh_max_port}",
		"Neighbor NAT deleted")

	grpc_client.assert_output(f"--delnat {vm1_name}",
		"NAT deleted")

	grpc_client.assert_output(f"--getnat {vm1_name}",
		nat_vip, negate=True)

	grpc_client.assert_output(f"--getnatinfo neigh --ipv4 {nat_vip}",
		nat_neigh_ul_dst, negate=True)

	grpc_client.assert_output(f"--delneighnat --ipv4 {nat_vip} --vni {vni} --min_port {nat_neigh_min_port} --max_port {nat_neigh_max_port}",
		"error 374")

	grpc_client.assert_output(f"--delnat {vm1_name}",
		"error 362")
