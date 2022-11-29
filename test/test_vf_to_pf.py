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


def reply_tcp_pkt_from_vm1():

	pkt_list = sniff(count=1, lfilter=is_tcp_pkt, iface=pf0_tap, timeout=2)
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

def test_vf_to_pf_network_nat_tcp(prepare_ipv4, grpc_client):

	# TODO(plague) I suspect that there is an occasional problem here
	# as this test is called immediately after the previous one, that established and then teared down the same route
	# there will be a race condition and the service needs more time this time around
	grpc_client.assert_output(f"--addnat {vm1_name} --ipv4 {nat_vip} --min_port {nat_local_min_port} --max_port {nat_local_max_port}",
		"Received underlay route")

	threading.Thread(target=reply_tcp_pkt_from_vm1).start()

	tcp_pkt = (Ether(dst=pf0_mac, src=vf0_mac, type=0x0800) /
			   IP(dst=public_ip, src=vf0_ip) /
			   TCP(sport=1240))
	delayed_sendp(tcp_pkt, vf0_tap)

	pkt_list = sniff(count=1, lfilter=is_tcp_pkt, iface=vf0_tap, timeout=2)
	assert len(pkt_list) == 1, \
		"No network-natted TCP packet received on PF"

	pkt = pkt_list[0]
	dst_ip = pkt[IP].dst
	dport = pkt[TCP].dport
	assert dst_ip == vf0_ip and dport == 1240, \
		f"Bad TCP packet (ip: {dst_ip}, dport: {dport})"

	grpc_client.assert_output(f"--delnat {vm1_name}",
		"NAT deleted")


# TODO: this can be done better with sniff(iface=[iface1, iface2], but ther is a regression in scany 2.4.5 that broke this
def encaped_tcp_in_ipv6_vip_responder(pf_name):
	pkt_list = sniff(count=1, lfilter=is_tcp_pkt, iface=pf_name, timeout=2)
	# with --port-redundancy, there are two listeners running and only one receives a packet
	if len(pkt_list) == 0:
		return
	pkt = pkt_list[0]
	reply_pkt = (Ether(dst=pkt[Ether].src, src=pkt[Ether].dst, type=0x86DD) /
				 IPv6(dst=ul_actual_src, src=pkt[IPv6].dst, nh=4) /
				 IP(dst=pkt[IP].src, src=pkt[IP].dst) /
				 TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport))
	delayed_sendp(reply_pkt, pf_name)

def test_vf_to_pf_vip_snat(prepare_ipv4, grpc_client, port_redundancy):

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

	pkt_list = sniff(count=1, lfilter=is_tcp_pkt, iface=vf1_tap, timeout=2)
	assert len(pkt_list) == 1, \
		"No TCP reply via VIP (SNAT)"

	grpc_client.assert_output(f"--delvip {vm2_name}",
		"VIP deleted")


# TODO: this can be done better with sniff(iface=[iface1, iface2], but ther is a regression in scany 2.4.5 that broke this
def reply_with_icmp_err_fragment_needed(pf_name):
	pkt_list = sniff(count=1, lfilter=is_tcp_pkt, iface=pf_name, timeout=2)
	# with --port-redundancy, there are two listeners running and only one receives a packet
	if len(pkt_list) == 0:
		return
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

def test_vm_nat_async_tcp_icmperr(prepare_ifaces, grpc_client, port_redundancy):

	grpc_client.assert_output(f"--addnat {vm1_name} --ipv4 {nat_vip} --min_port {nat_local_min_port} --max_port {nat_local_max_port}",
		"Received underlay route")

	threading.Thread(target=reply_with_icmp_err_fragment_needed, args=(pf0_tap,)).start();
	if (port_redundancy):
		threading.Thread(target=reply_with_icmp_err_fragment_needed, args=(pf1_tap,)).start();

	tcp_pkt = (Ether(dst=mc_mac, src=vf0_mac, type=0x0800) /
			   IP(dst=public_ip, src=vf0_ip) /
			   TCP(sport=1256, dport=500))
	delayed_sendp(tcp_pkt, vf0_tap)

	pkt_list = sniff(count=1, lfilter=is_icmp_pkt, iface=vf0_tap, timeout=5)
	assert len(pkt_list) == 1, \
		"Cannot receive asymmetric icmp pkt on pf"

	pkt = pkt_list[0]
	icmp_type = pkt[ICMP].type
	assert icmp_type == 3, \
		f"Received wrong icmp packet type: {icmp_type}"

	grpc_client.assert_output(f"--delnat {vm1_name}",
		"NAT deleted")
