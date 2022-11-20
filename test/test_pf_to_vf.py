import threading

from config import *
from helpers import *


def send_lb_pkt_to_pf():
	lb_pkt = (Ether(dst=mc_mac, src=pf0_mac, type=0x86DD) /
			  IPv6(dst=ul_actual_dst, src=ul_actual_src, nh=4) /
			  IP(dst=virtual_ip, src=public_ip) /
			  TCP(sport=1234, dport=80))
	time.sleep(3)
	sendp(lb_pkt, iface=pf0_tap)

def test_pf_to_vf_lb_tcp(add_machine, grpc_client):

	grpc_client.assert_output(f"--createlb {mylb} --vni {vni} --ipv4 {virtual_ip} --port 80 --protocol tcp",
		ul_actual_src)

	output = grpc_client.assert_output(f"--addlbpfx {vm1_name} --ipv4 {virtual_ip} --length 32",
		ul_short_src)
	vm1_target_lb_pfx_underlay = output.partition("\n")[0].partition(": ")[2]

	grpc_client.assert_output(f"--addlbvip {mylb} --t_ipv6 {vm1_target_lb_pfx_underlay}",
		"LB VIP added")

	threading.Thread(target=send_lb_pkt_to_pf).start()

	pkt_list = sniff(count=1, lfilter=is_tcp_pkt, iface=vf0_tap, timeout=7)
	assert len(pkt_list) == 1

	pkt = pkt_list[0]

	if Ether in pkt:
		pktether = pkt[Ether]
	if IP in pkt:
		pktip = pkt[IP]
	if TCP in pkt:
		pkttcp = pkt[TCP]

	assert pktip.dst == virtual_ip and pkttcp.dport == 80, 'Received wrong packet with ip:'+pktip.dst+" dport:"+str(pkttcp.dport)

	grpc_client.assert_output(f"--dellbpfx {vm1_name} --ipv4 {virtual_ip} --length 32",
		"LB prefix deleted")

	grpc_client.assert_output(f"--dellb {mylb}",
		"LB deleted")
