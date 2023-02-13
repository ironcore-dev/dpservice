import threading

from helpers import *


def test_network_nat_external_icmp_echo(prepare_ipv4, grpc_client):

	_, ipv6_nat  = grpc_client.assert_output(f"--addnat {vm1_name} --ipv4 {nat_vip} --min_port {nat_local_min_port} --max_port {nat_local_max_port}",
		"Received underlay route")

	icmp_pkt = (Ether(dst=mc_mac, src=pf0_mac, type=0x86DD) /
			    IPv6(dst=ipv6_nat, src=ul_actual_src, nh=4) /
			    IP(dst=nat_vip, src=public_ip) /
			    ICMP(type=8, id=0x0040))
	answer = srp1(icmp_pkt, iface=pf0_tap, timeout=2)
	assert answer and is_icmp_pkt(answer), \
		"No ECHO reply"

	grpc_client.assert_output(f"--delnat {vm1_name}",
		"NAT deleted")


def send_bounce_pkt_to_pf(ipv6_nat):
	bouce_pkt = (Ether(dst=mc_mac, src=pf0_mac, type=0x86DD) /
				 IPv6(dst=ipv6_nat, src=ul_actual_src, nh=4) /
				 IP(dst=nat_vip, src=public_ip) /
				 TCP(sport=8989, dport=510))
	delayed_sendp(bouce_pkt, pf0_tap)

def test_network_nat_pkt_relay(prepare_ifaces, grpc_client):

	_, ipv6_nat = grpc_client.assert_output(f"--addnat {vm1_name} --ipv4 {nat_vip} --min_port {nat_local_min_port} --max_port {nat_local_max_port}",
		ul_short_src)
	grpc_client.assert_output(f"--addneighnat --ipv4 {nat_vip} --vni {vni} --min_port {nat_neigh_min_port} --max_port {nat_neigh_max_port} --t_ipv6 {nat_neigh_ul_dst}",
		"Neighbor NAT added")

	threading.Thread(target=send_bounce_pkt_to_pf,  args=(ipv6_nat,)).start()

	# it seems that pkt_list[0] is the injected packet
	pkt_list = sniff(count=2, lfilter=is_tcp_pkt, iface=pf0_tap, timeout=5)
	assert len(pkt_list) == 2, \
		"No bounce packet received"

	pkt = pkt_list[1]
	dst_ip = pkt[IPv6].dst
	dport = pkt[TCP].dport
	assert dst_ip == nat_neigh_ul_dst and dport == 510, \
		f"Wrong network-nat relayed packet (outer dst ipv6: {dst_ip}, dport: {dport})"

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
		"error 451")
