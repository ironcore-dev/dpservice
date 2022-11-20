import threading
import time

from config import *
from helpers import *
from responders import *


def test_vf_to_vf_tcp(add_machine, request_ip_vf0, request_ip_vf1):

	threading.Thread(target=vf_to_vf_tcp_vf1_responder).start()

	time.sleep(1)

	tcp_pkt = (Ether(dst=vf1_mac, src=vf0_mac, type=0x0800) /
			   IP(dst=vf1_ip, src=vf0_ip) /
			   TCP())
	sendp(tcp_pkt, iface=vf0_tap)

	pkt_list = sniff(count=1, lfilter=is_tcp_pkt, iface=vf0_tap, timeout=2)
	assert len(pkt_list) == 1


def test_vf_to_vf_vip_dnat(add_machine, request_ip_vf0, request_ip_vf1, grpc_client):

	threading.Thread(target=vf_to_vf_tcp_vf1_responder).start()

	grpc_client.assert_output(f"--addvip {vm2_name} --ipv4 {virtual_ip}",
		ul_actual_src)

	time.sleep(1)

	# vm1 (vf0) -> vm2 (vf2), vm2 has VIP, send packet to VIP from vm1 side, whether the packet is received
	# and sent back by vm2 (DNAT)
	tcp_pkt = (Ether(dst=vf1_mac, src=vf0_mac, type=0x0800) /
			   IP(dst=virtual_ip, src=vf0_ip) /
			   TCP(sport=1200))
	sendp(tcp_pkt, iface=vf0_tap)

	pkt_list = sniff(count=1, lfilter=is_tcp_pkt, iface=vf0_tap, timeout=2)
	assert len(pkt_list) == 1

	grpc_client.assert_output(f"--delvip {vm2_name}",
		"VIP deleted")
