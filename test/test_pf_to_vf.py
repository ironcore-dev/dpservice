import threading

from helpers import *


def send_lb_pkt_to_pf(lb_ipv6):
	lb_pkt = (Ether(dst=mc_mac, src=pf0_mac, type=0x86DD) /
			  IPv6(dst=lb_ipv6, src=ul_actual_src, nh=4) /
			  IP(dst=virtual_ip, src=public_ip) /
			  TCP(sport=1234, dport=80))
	delayed_sendp(lb_pkt, pf0_tap)

def test_pf_to_vf_lb_tcp(prepare_ifaces, grpc_client):

	_, lb_ipv6 = grpc_client.assert_output(f"--createlb {mylb} --vni {vni} --ipv4 {virtual_ip} --port 80 --protocol tcp",
		ul_short_src)

	_, vm1_target_lb_pfx_underlay = grpc_client.assert_output(f"--addlbpfx {vm1_name} --ipv4 {virtual_ip} --length 32",
		ul_short_src)

	#vm1_target_lb_pfx_underlay = output.partition("\n")[0].partition(": ")[2]
	grpc_client.assert_output(f"--addlbvip {mylb} --t_ipv6 {vm1_target_lb_pfx_underlay}",
		"LB VIP added")

	threading.Thread(target=send_lb_pkt_to_pf, args=(lb_ipv6,)).start()

	pkt_list = sniff(count=1, lfilter=is_tcp_pkt, iface=vf0_tap, timeout=2)
	assert len(pkt_list) == 1, \
		"No packets received"

	pkt = pkt_list[0]
	dst_ip = pkt[IP].dst
	dport = pkt[TCP].dport
	assert dst_ip == virtual_ip and dport == 80, \
		f"Wrong packet received (ip: {dst_ip}, dport: {dport})"

	grpc_client.assert_output(f"--dellbpfx {vm1_name} --ipv4 {virtual_ip} --length 32",
		"LB prefix deleted")

	grpc_client.assert_output(f"--dellb {mylb}",
		"LB deleted")
