#!/usr/bin/env python3

import argparse
import multiprocessing
import sys
import time
from datetime import datetime
from scapy.all import *


def is_ipip_pkt(pkt):
	return pkt[IPv6].nh == 4 or pkt[IPv6].nh == 41

def is_virtsvc_pkt(pkt):
	return pkt[IPv6].src in opts.virtsvc or pkt[IPv6].dst in opts.virtsvc

# Filter for underlay packets not sent by this script (marked by the Traffic Class field)
def is_ul_pkt(pkt):
	return IPv6 in pkt and pkt[IPv6].tc == 0 and (is_ipip_pkt(pkt) or is_virtsvc_pkt(pkt))

# Sends packets back over the interface
def sender_loop(q):
	try:
		while True:
			iface, pkt = q.get()
			# Give receiver time to enter sniff()
			time.sleep(0.1)
			sendp(pkt, iface=iface, verbose=opts.verbose > 1)
	except KeyboardInterrupt:
		return

# Simply receives all underlay packets and passes them to the sender with appropriate changes
def receiver_loop(q, iface, mac):
	if opts.verbose:
		print(f"Listening on {iface}, mangling packets from {mac}")
	while True:
		pkts = sniff(iface=iface, count=1, lfilter=is_ul_pkt)
		if len(pkts) != 1:
			print(f"Sniffing on {iface} interrupted", file=sys.stderr)
			exit(1)
		pkt = pkts[0]
		if opts.verbose:
			summary = f"{pkt.sprintf('%Ether.src% -> %Ether.dst% / %IPv6.src% -> %IPv6.dst%')} / {pkt.summary().split(' / ', 2)[2]}"
			print(f"{datetime.now()} {iface}: {summary}")
		# Mark the sent-out packet as to not be sniffed by the receiver
		pkt[IPv6].tc = 0x0C
		# For packets originating from PF, change them so they do not pass directly to dpservice
		# But are caught by pytest instead
		if pkt[Ether].src == mac:
			pkt[Ether].type = 0x1337
		q.put((iface, pkt))


class ReflectAction(argparse.Action):
	def __call__(self, parser, namespace, values, option_string=None):
		for value in values:
			spec = value.split(',')
			if len(spec) != 2:
				raise argparse.ArgumentError(self, f"Invalid IFACE,MAC tuple given: '{value}'")
			getattr(namespace, self.dest).append(value)

if __name__ == '__main__':
	parser = argparse.ArgumentParser(description="Packet reflector for dpservice pytest suite")
	parser.add_argument('-v', '--verbose', action='count', default=0, help="more verbose output (use multiple times)")
	parser.add_argument('--virtsvc', action='append', default=[], help="virtual service endpoint(s)")
	parser.add_argument('reflect', metavar='IFACE,MAC', default=[], nargs='+', action=ReflectAction, help="interface(s) to listen on and *remote* MAC(s) to mangle")
	opts = parser.parse_args()

	q = multiprocessing.Queue()

	for spec in opts.reflect:
		iface, mac = spec.split(',')
		multiprocessing.Process(target=receiver_loop, args=(q, iface, mac)).start()

	sender_loop(q)
