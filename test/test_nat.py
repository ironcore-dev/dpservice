import threading

from helpers import *


def test_network_nat_external_icmp_echo(prepare_ipv4, grpc_client):
	nat_ipv6 = grpc_client.addnat(vm1_name, nat_vip, nat_local_min_port, nat_local_max_port)
	icmp_pkt = (Ether(dst=mc_mac, src=pf0_mac, type=0x86DD) /
			    IPv6(dst=nat_ipv6, src=ul_actual_src, nh=4) /
			    IP(dst=nat_vip, src=public_ip) /
			    ICMP(type=8, id=0x0040))
	answer = srp1(icmp_pkt, iface=pf0_tap, timeout=sniff_timeout)
	validate_checksums(answer)
	assert answer and is_icmp_pkt(answer), \
		"No ECHO reply"
	grpc_client.delnat(vm1_name)


def send_bounce_pkt_to_pf(ipv6_nat):
	bouce_pkt = (Ether(dst=mc_mac, src=pf0_mac, type=0x86DD) /
				 IPv6(dst=ipv6_nat, src=ul_actual_src, nh=4) /
				 IP(dst=nat_vip, src=public_ip) /
				 TCP(sport=8989, dport=510))
	delayed_sendp(bouce_pkt, pf0_tap)

def test_network_nat_pkt_relay(prepare_ifaces, grpc_client):

	nat_ipv6 = grpc_client.addnat(vm1_name, nat_vip, nat_local_min_port, nat_local_max_port)
	grpc_client.addneighnat(nat_vip, vni, nat_neigh_min_port, nat_neigh_max_port, nat_neigh_ul_dst)

	threading.Thread(target=send_bounce_pkt_to_pf,  args=(nat_ipv6,)).start()

	# it seems that we also receive the injected packet, skip it
	pkt = sniff_packet(pf0_tap, is_tcp_pkt, skip=1)
	dst_ip = pkt[IPv6].dst
	dport = pkt[TCP].dport
	assert dst_ip == nat_neigh_ul_dst and dport == 510, \
		f"Wrong network-nat relayed packet (outer dst ipv6: {dst_ip}, dport: {dport})"

	grpc_client.assert_output(f"--getnat {vm1_name}",
		f"Received NAT IP {nat_vip} with min port: {nat_local_min_port} and max port: {nat_local_max_port} underlay {nat_ipv6}")
	grpc_client.assert_output(f"--getnatinfo neigh --ipv4 {nat_vip}",
		nat_neigh_ul_dst)

	grpc_client.delneighnat(nat_vip, vni, nat_neigh_min_port, nat_neigh_max_port)
	grpc_client.delnat(vm1_name)
	grpc_client.assert_output(f"--getnat {vm1_name}",
		nat_vip, negate=True)
	grpc_client.assert_output(f"--getnatinfo neigh --ipv4 {nat_vip}",
		nat_neigh_ul_dst, negate=True)

	grpc_client.assert_output(f"--delneighnat --ipv4 {nat_vip} --vni {vni} --min_port {nat_neigh_min_port} --max_port {nat_neigh_max_port}",
		"error 374")
	grpc_client.assert_output(f"--delnat {vm1_name}",
		"error 451")

def test_network_nat_vip_co_existence_on_same_vm(prepare_ifaces, grpc_client):
	vip_ipv6 = grpc_client.addvip(vm1_name, virtual_ip)
	nat_ipv6 = grpc_client.addnat(vm1_name, nat_vip, nat_local_min_port, nat_local_max_port)
	grpc_client.assert_output(f"--getnat {vm1_name}",
		f"Received NAT IP {nat_vip} with min port: {nat_local_min_port} and max port: {nat_local_max_port} underlay {nat_ipv6}")
	grpc_client.assert_output(f"--getvip {vm1_name}",
		f"Received VIP {virtual_ip} underlayroute {vip_ipv6}")
	grpc_client.delnat(vm1_name)
	grpc_client.delvip(vm1_name)
