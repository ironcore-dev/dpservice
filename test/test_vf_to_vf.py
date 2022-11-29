import threading

from helpers import *


def vf_to_vf_tcp_responder(vf_name):
	pkt = sniff(count=1, lfilter=is_tcp_pkt, iface=vf_name, timeout=2)[0]
	reply_pkt = (Ether(dst=pkt[Ether].src, src=pkt[Ether].dst, type=0x0800) /
				 IP(dst=pkt[IP].src, src=pkt[IP].dst) /
				 TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport))
	delayed_sendp(reply_pkt, vf_name)


def test_vf_to_vf_tcp(prepare_ipv4):

	threading.Thread(target=vf_to_vf_tcp_responder, args=(vf1_tap,)).start()

	tcp_pkt = (Ether(dst=vf1_mac, src=vf0_mac, type=0x0800) /
			   IP(dst=vf1_ip, src=vf0_ip) /
			   TCP())
	delayed_sendp(tcp_pkt, vf0_tap)

	pkt_list = sniff(count=1, lfilter=is_tcp_pkt, iface=vf0_tap, timeout=2)
	assert len(pkt_list) == 1, \
		"No TCP reply"


def test_vf_to_vf_vip_dnat(prepare_ipv4, grpc_client):

	threading.Thread(target=vf_to_vf_tcp_responder, args=(vf1_tap,)).start()

	grpc_client.assert_output(f"--addvip {vm2_name} --ipv4 {virtual_ip}",
		ul_actual_src)

	# vm1 (vf0) -> vm2 (vf2), vm2 has VIP, send packet to VIP from vm1 side, whether the packet is received
	# and sent back by vm2 (DNAT)
	tcp_pkt = (Ether(dst=vf1_mac, src=vf0_mac, type=0x0800) /
			   IP(dst=virtual_ip, src=vf0_ip) /
			   TCP(sport=1200))
	delayed_sendp(tcp_pkt, vf0_tap)

	pkt_list = sniff(count=1, lfilter=is_tcp_pkt, iface=vf0_tap, timeout=2)
	assert len(pkt_list) == 1, \
		"No TCP reply"

	grpc_client.assert_output(f"--delvip {vm2_name}",
		"VIP deleted")
