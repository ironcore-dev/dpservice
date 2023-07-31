import pytest
import threading

from helpers import *


def test_network_nat_external_icmp_echo(prepare_ipv4, grpc_client):
	nat_ul_ipv6 = grpc_client.addnat(VM1.name, nat_vip, nat_local_min_port, nat_local_max_port)
	icmp_pkt = (Ether(dst=ipv6_multicast_mac, src=PF0.mac, type=0x86DD) /
			    IPv6(dst=nat_ul_ipv6, src=router_ul_ipv6, nh=4) /
			    IP(dst=nat_vip, src=public_ip) /
			    ICMP(type=8, id=0x0040))
	answer = srp1(icmp_pkt, iface=PF0.tap, timeout=sniff_timeout)
	validate_checksums(answer)
	assert answer and is_icmp_pkt(answer), \
		"No ECHO reply"
	grpc_client.delnat(VM1.name)


def send_bounce_pkt_to_pf(ipv6_nat):
	bouce_pkt = (Ether(dst=ipv6_multicast_mac, src=PF0.mac, type=0x86DD) /
				 IPv6(dst=ipv6_nat, src=router_ul_ipv6, nh=4) /
				 IP(dst=nat_vip, src=public_ip) /
				 TCP(sport=8989, dport=510))
	delayed_sendp(bouce_pkt, PF0.tap)

def test_network_nat_pkt_relay(prepare_ifaces, grpc_client):

	nat_ul_ipv6 = grpc_client.addnat(VM1.name, nat_vip, nat_local_min_port, nat_local_max_port)
	grpc_client.addneighnat(nat_vip, vni1, nat_neigh_min_port, nat_neigh_max_port, neigh_vni1_ul_ipv6)
	# Add another neighbor and remove it to check if that does not break the other entry
	# (cannot be done afterwards as the DNAT table will have already been changed by this test)
	# Also do the same with another NAT VIP on the same VNI
	grpc_client.addneighnat(nat_vip, vni1, nat_neigh_max_port+1, nat_neigh_max_port+2, neigh_vni1_ul_ipv6)
	grpc_client.addnat(VM2.name, nat_vip, nat_local_max_port+10, nat_local_max_port+11)
	grpc_client.delneighnat(nat_vip, vni1, nat_neigh_max_port+1, nat_neigh_max_port+2)
	grpc_client.delnat(VM2.name)

	threading.Thread(target=send_bounce_pkt_to_pf, args=(nat_ul_ipv6,)).start()

	# PF0 receives both the incoming packet and the relayed one, skip the first
	pkt = sniff_packet(PF0.tap, is_tcp_pkt, skip=1)
	dst_ip = pkt[IPv6].dst
	dport = pkt[TCP].dport
	assert dst_ip == neigh_vni1_ul_ipv6 and dport == 510, \
		f"Wrong network-nat relayed packet (outer dst ipv6: {dst_ip}, dport: {dport})"

	localspec = { 'nat_ip': nat_vip, 'underlay_route': nat_ul_ipv6, 'min_port': nat_local_min_port, 'max_port': nat_local_max_port }
	spec = grpc_client.getnat(VM1.name)
	assert spec == localspec, \
		"Failed to add NAT properly"

	neighspec = { 'underlay_route': neigh_vni1_ul_ipv6, 'min_port': nat_neigh_min_port, 'max_port': nat_neigh_max_port, 'vni': vni1 }
	specs = grpc_client.listneighnats(nat_vip)
	assert specs == [neighspec], \
		"Invalid neighboring NAT list"

	grpc_client.delneighnat(nat_vip, vni1, nat_neigh_min_port, nat_neigh_max_port)
	grpc_client.delnat(VM1.name)

	grpc_client.expect_error(341).getnat(VM1.name)

	specs = grpc_client.listneighnats(nat_vip)
	assert len(specs) == 0, \
		"Failed to delete neighboring NAT entries properly"

	grpc_client.expect_error(201).delneighnat(nat_vip, vni1, nat_neigh_min_port, nat_neigh_max_port)
	grpc_client.expect_error(341).delnat(VM1.name)


def send_foreign_ip_nat_pkt_to_pf(ipv6_nat):
	bouce_pkt = (Ether(dst=ipv6_multicast_mac, src=PF0.mac, type=0x86DD) /
				 IPv6(dst=ipv6_nat, src=router_ul_ipv6, nh=4) /
				 IP(dst="1.2.3.4", src=public_ip) /
				 TCP(sport=8989, dport=510))
	delayed_sendp(bouce_pkt, PF0.tap)

def test_network_nat_foreign_ip(prepare_ifaces, grpc_client):

	nat_ul_ipv6 = grpc_client.addnat(VM1.name, nat_vip, nat_local_min_port, nat_local_max_port)

	threading.Thread(target=send_foreign_ip_nat_pkt_to_pf, args=(nat_ul_ipv6,)).start()

	# PF0 receives both the incoming packet and the relayed one, skip the first
	pkt_list = sniff(count=2, lfilter=is_ipip_pkt, iface=PF0.tap, timeout=sniff_short_timeout)
	assert len(pkt_list) > 0, \
		f"No reply on {iface}"
	if len(pkt_list) > 1:
		pkt_list[1].show()
		assert False, "Packet was not dropped"

	grpc_client.delnat(VM1.name)


def test_network_nat_vip_co_existence_on_same_vm(prepare_ifaces, grpc_client):
	vip_ul_ipv6 = grpc_client.addvip(VM1.name, vip_vip)
	nat_ul_ipv6 = grpc_client.addnat(VM1.name, nat_vip, nat_local_min_port, nat_local_max_port)

	natspec = { 'nat_ip': nat_vip, 'underlay_route': nat_ul_ipv6, 'min_port': nat_local_min_port, 'max_port': nat_local_max_port }
	spec = grpc_client.getnat(VM1.name)
	assert spec == natspec, \
		"Failed to add NAT properly"

	vipspec = { 'vip_ip': vip_vip, 'underlay_route': vip_ul_ipv6 }
	spec = grpc_client.getvip(VM1.name)
	assert spec == vipspec, \
		"Failed to add VIP properly"

	grpc_client.delnat(VM1.name)
	grpc_client.delvip(VM1.name)


def router_nat_vip(dst_ipv6, check_ipv4):
	pkt = sniff_packet(PF0.tap, is_tcp_pkt)
	assert pkt[IP].src == check_ipv4, \
		f"Bad request (src ip: {pkt[IP].src})"
	reply_pkt = (Ether(dst=pkt[Ether].src, src=pkt[Ether].dst, type=0x86DD) /
				 IPv6(dst=dst_ipv6, src=pkt[IPv6].dst, nh=4) /
				 IP(src=pkt[IP].src, dst=pkt[IP].dst) /
				 TCP(dport=pkt[TCP].dport, sport=pkt[TCP].sport))
	delayed_sendp(reply_pkt, PF0.tap)

def test_network_nat_to_vip_on_another_vni(prepare_ipv4, grpc_client, port_redundancy):

	if port_redundancy:
		pytest.skip("Port redundancy is not supported for NAT(vni1) <-> VIP(vni2) test")

	nat_ul_ipv6 = grpc_client.addnat(VM1.name, nat_vip, nat_local_min_port, nat_local_max_port)
	vip_ul_ipv6 = grpc_client.addvip(VM3.name, vip_vip)

	threading.Thread(target=router_nat_vip, args=(vip_ul_ipv6, nat_vip)).start()
	grpc_client.addfwallrule(VM3.name, "fw0-vm3", proto="tcp", dst_port_min=1024, dst_port_max=1024)
	tcp_pkt = (Ether(dst=PF0.mac, src=VM1.mac, type=0x0800) /
			   IP(dst=vip_vip, src=VM1.ip) /
			   TCP(dport=1024))
	delayed_sendp(tcp_pkt, VM1.tap)

	pkt = sniff_packet(VM3.tap, is_tcp_pkt)
	assert pkt[IP].dst == VM3.ip, \
		f"Invalid VIPped destination IP {pkt[IP].dst}"

	threading.Thread(target=router_nat_vip, args=(nat_ul_ipv6, vip_vip)).start()

	reply_pkt = (Ether(dst=pkt[Ether].src, src=pkt[Ether].dst, type=0x0800) /
				 IP(dst=pkt[IP].src, src=pkt[IP].dst) /
				 TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport))
	delayed_sendp(reply_pkt, VM3.tap)

	pkt = sniff_packet(VM1.tap, is_tcp_pkt)
	assert pkt[IP].dst == VM1.ip, \
		f"Invalid NATted destination IP {pkt[IP].dst}"

	grpc_client.delvip(VM3.name)
	grpc_client.delnat(VM1.name)
	grpc_client.delfwallrule(VM3.name, "fw0-vm3")
