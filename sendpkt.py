from scapy.all import *

pf0_mac = "90:3c:b3:33:72:fb"
vf0_mac = "66:73:20:a9:a7:00"
public_ip = "45.86.6.6"
vf0_ip ="176.44.33.12"
vf0_tap = "dtapvf_0"

def is_tcp_pkt(pkt):
	if TCP in pkt:
		return True
	return False

def send_simulate_pkt():
	tcp_pkt = Ether(dst = pf0_mac, src = vf0_mac, type = 0x0800) / IP(dst = public_ip, src = vf0_ip) / TCP(sport=1240)
	sendp(tcp_pkt, iface = vf0_tap)

	pkt_list = sniff(count=1,lfilter=is_tcp_pkt,iface=vf0_tap,timeout=20)
	if len(pkt_list)==0:
		return 

	pkt=pkt_list[0]
	pkt.show()



if __name__ == "__main__":
	dhcp_request(iface=vf0_tap, timeout=5)
	send_simulate_pkt()