# SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
# SPDX-License-Identifier: Apache-2.0

from config import *
from helpers import *

#LB Test helpers

def router_loopback(dst_ipv6, check_ipv4_src, check_ipv4_dst):
	pkt = sniff_packet(PF0.tap, is_tcp_pkt)
	assert pkt[IP].dst == check_ipv4_dst, \
		f"Invalid LB->VM destination IP {pkt[IP].dst}"
	assert pkt[IP].src == check_ipv4_src, \
		f"Bad request (src ip: {pkt[IP].src})"
	reply_pkt = (Ether(dst=pkt[Ether].src, src=pkt[Ether].dst, type=0x86DD) /
				 IPv6(dst=dst_ipv6, src=pkt[IPv6].dst, nh=4) /
				 IP(src=pkt[IP].src, dst=pkt[IP].dst) /
				 TCP(dport=pkt[TCP].dport, sport=pkt[TCP].sport))
	delayed_sendp(reply_pkt, PF0.tap)

def communicate_vip_lb(vm, lb_ipv6, src_ipv6, src_ipv4, vf_tap, sport):
	threading.Thread(target=router_loopback, args=(lb_ipv6, src_ipv4, lb_ip)).start()
	# vm(VIP) HTTP request to LB(VM1,VM2) server
	vm_pkt = (Ether(dst=PF0.mac, src=vm.mac, type=0x0800) /
			   IP(dst=lb_ip, src=vm.ip) /
			   TCP(sport=sport, dport=80))
	delayed_sendp(vm_pkt, vm.tap)
	# LB(VM1,VM2) server request from the router
	srv_pkt = sniff_packet(vf_tap, is_tcp_pkt)
	assert srv_pkt[IP].dst == lb_ip, \
		f"Invalid LB->VM destination IP {srv_pkt[IP].dst}"
	assert srv_pkt[TCP].dport == 80, \
		"Invalid server port"

	threading.Thread(target=router_loopback, args=(src_ipv6, lb_ip, src_ipv4)).start()
	# HTTP response back to VIP(vm)
	srv_reply = (Ether(dst=srv_pkt[Ether].src, src=srv_pkt[Ether].dst, type=0x0800) /
				 IP(dst=srv_pkt[IP].src, src=srv_pkt[IP].dst) /
				 TCP(sport=srv_pkt[TCP].dport, dport=srv_pkt[TCP].sport))
	delayed_sendp(srv_reply, vf_tap)
	# HTTP response from the router on vm(VIP)
	vm_reply = sniff_packet(vm.tap, is_tcp_pkt)
	assert vm_reply[IP].dst == vm.ip, \
		f"Invalid VIPped destination IP {vm_reply[IP].dst}"
	assert vm_reply[TCP].sport == 80, \
		f"Invalid server reply port {vm_reply[TCP].sport}"