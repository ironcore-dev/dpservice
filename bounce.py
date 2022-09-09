from scapy.all import *

pf0_mac = "90:3c:b3:33:72:fb"
vf0_mac = "66:73:20:a9:a7:00"
public_ip = "45.86.6.6"
vf0_ip ="176.44.33.12"
vf0_tap = "dtapvf_0"
pf0_tap = "dtap0"
pf1_tap = "dtap1"
ul_actual_src="2a10:afc0:e01f:f403:0:64::"
ul_actual_dst="2a10:afc0:e01f:f408:0:64::"
mc_mac = "33:33:00:00:00:01"

extern_ipv4 = "45.88.77.66"

def send_simulate_pkt():
	# sendp(reply_pkt, iface=pf0_tap)
	
	bouce_pkt = Ether(dst=mc_mac, src=pf0_mac, type=0x86DD)/IPv6(dst=ul_actual_src, src=ul_actual_dst, nh=4)/IP(dst=extern_ipv4, src=public_ip) /TCP(sport=8989, dport=2100)
	# sendp(bouce_pkt, iface=pf0_tap)
	answer, unanswered = srp(bouce_pkt, iface=pf0_tap, timeout=10)
	# pkt_list = sniff(count=1,lfilter=is_tcp_pkt,iface=pf0_tap,timeout=60)
	if not answer:
		return 
	answer.show()
	# pkt=pkt_list[0]
	# pkt.show()

def is_tcp_pkt(pkt):
	if TCP in pkt:
		return True
	return False


if __name__ == "__main__":
	send_simulate_pkt()