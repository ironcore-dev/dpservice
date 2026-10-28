#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
# SPDX-License-Identifier: Apache-2.0

# The application the Linux peer answers with, run inside the peer's network namespace by
# XfrmPeer. It knows nothing about IPsec: every packet it sees has already been decrypted by
# the kernel, and everything it sends is encrypted on the way out. That is the point - what it
# receives is the plaintext dpservice sent, or the test has failed before this ever ran.

import socket
import sys

max_payload = 2048


def main():
	address = (sys.argv[1], int(sys.argv[2]))
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sock.bind(address)

	# The parent sends nothing until this line arrives. A request that gets here before bind()
	# has returned is answered by nobody at all and simply disappears, which would show up as
	# an occasional missing packet rather than as a failure anyone could read.
	print("listening", flush=True)

	while True:
		payload, sender = sock.recvfrom(max_payload)
		sock.sendto(payload, sender)


main()
