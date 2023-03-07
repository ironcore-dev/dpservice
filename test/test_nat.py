import pytest
import threading

from helpers import *


def test_network_nat_external_icmp_echo(prepare_ipv4, grpc_client):
	nat_ipv6 = grpc_client.addnat(vm1_name, nat_vip, nat_local_min_port, nat_local_max_port)
	icmp_pkt = (Ether(dst=ipv6_multicast_mac, src=pf0_mac, type=0x86DD) /
			    IPv6(dst=nat_ipv6, src=router_ul_ipv6, nh=4) /
			    IP(dst=nat_vip, src=public_ip) /
			    ICMP(type=8, id=0x0040))
	answer = srp1(icmp_pkt, iface=pf0_tap, timeout=sniff_timeout)
	validate_checksums(answer)
	assert answer and is_icmp_pkt(answer), \
		"No ECHO reply"
	grpc_client.delnat(vm1_name)


def send_bounce_pkt_to_pf(ipv6_nat):
	bouce_pkt = (Ether(dst=ipv6_multicast_mac, src=pf0_mac, type=0x86DD) /
				 IPv6(dst=ipv6_nat, src=router_ul_ipv6, nh=4) /
				 IP(dst=nat_vip, src=public_ip) /
				 TCP(sport=8989, dport=510))
	delayed_sendp(bouce_pkt, pf0_tap)

def test_network_nat_pkt_relay(prepare_ifaces, grpc_client):

	nat_ipv6 = grpc_client.addnat(vm1_name, nat_vip, nat_local_min_port, nat_local_max_port)
	grpc_client.addneighnat(nat_vip, vni1, nat_neigh_min_port, nat_neigh_max_port, neigh_vni1_ul_ipv6)

	threading.Thread(target=send_bounce_pkt_to_pf,  args=(nat_ipv6,)).start()

	# it seems that we also receive the injected packet, skip it
	pkt = sniff_packet(pf0_tap, is_tcp_pkt, skip=1)
	dst_ip = pkt[IPv6].dst
	dport = pkt[TCP].dport
	assert dst_ip == neigh_vni1_ul_ipv6 and dport == 510, \
		f"Wrong network-nat relayed packet (outer dst ipv6: {dst_ip}, dport: {dport})"

	grpc_client.assert_output(f"--getnat {vm1_name}",
		f"Received NAT IP {nat_vip} with min port: {nat_local_min_port} and max port: {nat_local_max_port} underlay {nat_ipv6}")
	grpc_client.assert_output(f"--getnatinfo neigh --ipv4 {nat_vip}",
		neigh_vni1_ul_ipv6)

	grpc_client.delneighnat(nat_vip, vni1, nat_neigh_min_port, nat_neigh_max_port)
	grpc_client.delnat(vm1_name)
	grpc_client.assert_output(f"--getnat {vm1_name}",
		nat_vip, negate=True)
	grpc_client.assert_output(f"--getnatinfo neigh --ipv4 {nat_vip}",
		neigh_vni1_ul_ipv6, negate=True)

	grpc_client.assert_output(f"--delneighnat --ipv4 {nat_vip} --vni {vni1} --min_port {nat_neigh_min_port} --max_port {nat_neigh_max_port}",
		"error 374")
	grpc_client.assert_output(f"--delnat {vm1_name}",
		"error 451")


def test_network_nat_vip_co_existence_on_same_vm(prepare_ifaces, grpc_client):
	vip_ipv6 = grpc_client.addvip(vm1_name, vip_vip)
	nat_ipv6 = grpc_client.addnat(vm1_name, nat_vip, nat_local_min_port, nat_local_max_port)
	grpc_client.assert_output(f"--getnat {vm1_name}",
		f"Received NAT IP {nat_vip} with min port: {nat_local_min_port} and max port: {nat_local_max_port} underlay {nat_ipv6}")
	grpc_client.assert_output(f"--getvip {vm1_name}",
		f"Received VIP {vip_vip} underlayroute {vip_ipv6}")
	grpc_client.delnat(vm1_name)
	grpc_client.delvip(vm1_name)


def router_nat_vip(dst_ipv6, check_ipv4):
	pkt = sniff_packet(pf0_tap, is_tcp_pkt)
	assert pkt[IP].src == check_ipv4, \
		f"Bad request (src ip: {pkt[IP].src})"
	reply_pkt = (Ether(dst=pkt[Ether].src, src=pkt[Ether].dst, type=0x86DD) /
				 IPv6(dst=dst_ipv6, src=pkt[IPv6].dst, nh=4) /
				 IP(src=pkt[IP].src, dst=pkt[IP].dst) /
				 TCP(dport=pkt[TCP].dport, sport=pkt[TCP].sport))
	delayed_sendp(reply_pkt, pf0_tap)

def test_network_nat_to_vip_on_another_vni(prepare_ipv4, grpc_client, port_redundancy):

	if port_redundancy:
		pytest.skip("Port redundancy is not supported for NAT(vni1) <-> VIP(vni2) test")

	# establish a VM in another VNI on the same host
	vm3_ipv6 = grpc_client.addmachine(vm3_name, vf2_pci, vni2, vf2_ip, vf2_ipv6)
	grpc_client.addroute_ipv4(vni2, "0.0.0.0", 0, vni2, router_ul_ipv6)
	request_ip(vf2_tap, vf2_mac, vf2_ip)

	nat_ipv6 = grpc_client.addnat(vm1_name, nat_vip, nat_local_min_port, nat_local_max_port)
	vip_ipv6 = grpc_client.addvip(vm3_name, vip_vip)

	threading.Thread(target=router_nat_vip, args=(vip_ipv6, nat_vip)).start()

	tcp_pkt = (Ether(dst=pf0_mac, src=vf0_mac, type=0x0800) /
			   IP(dst=vip_vip, src=vf0_ip) /
			   TCP())
	delayed_sendp(tcp_pkt, vf0_tap)

	pkt = sniff_packet(vf2_tap, is_tcp_pkt)
	assert pkt[IP].dst == vf2_ip, \
		f"Invalid VIPped destination IP {pkt[IP].dst}"

	threading.Thread(target=router_nat_vip, args=(nat_ipv6, vip_vip)).start()

	reply_pkt = (Ether(dst=pkt[Ether].src, src=pkt[Ether].dst, type=0x0800) /
				 IP(dst=pkt[IP].src, src=pkt[IP].dst) /
				 TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport))
	delayed_sendp(reply_pkt, vf2_tap)

	pkt = sniff_packet(vf0_tap, is_tcp_pkt)
	assert pkt[IP].dst == vf0_ip, \
		f"Invalid NATted destination IP {pkt[IP].dst}"

	grpc_client.delvip(vm3_name)
	grpc_client.delnat(vm1_name)
	grpc_client.delroute_ipv4(vni2, "0.0.0.0", 0)
	grpc_client.delmachine(vm3_name)
