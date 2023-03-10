import threading

from helpers import *


def send_lb_pkt_to_pf(lb_ul_ipv6):
	lb_pkt = (Ether(dst=ipv6_multicast_mac, src=PF0.mac, type=0x86DD) /
			  IPv6(dst=lb_ul_ipv6, src=router_ul_ipv6, nh=4) /
			  IP(dst=lb_ip, src=public_ip) /
			  TCP(sport=1234, dport=80))
	delayed_sendp(lb_pkt, PF0.tap)

def test_pf_to_vf_lb_tcp(prepare_ifaces, grpc_client):

	lb_ul_ipv6 = grpc_client.createlb(lb_name, vni1, lb_ip, 80, "tcp")
	lbpfx_ul_ipv6 = grpc_client.addlbpfx(VM1.name, lb_ip)
	grpc_client.addlbvip(lb_name, lbpfx_ul_ipv6)

	threading.Thread(target=send_lb_pkt_to_pf, args=(lb_ul_ipv6,)).start()

	pkt = sniff_packet(VM1.tap, is_tcp_pkt)
	dst_ip = pkt[IP].dst
	dport = pkt[TCP].dport
	assert dst_ip == lb_ip and dport == 80, \
		f"Wrong packet received (ip: {dst_ip}, dport: {dport})"

	grpc_client.dellbvip(VM1.name, lbpfx_ul_ipv6)
	grpc_client.dellbpfx(VM1.name, lb_ip)
	grpc_client.dellb(lb_name)

	# TODO: Currently, to use this test again with the same port(s)
	# you need to wait for the used flow to be aged-out (done every 30s)
	# If TCP RST is implemented down the line, this can be overcome
