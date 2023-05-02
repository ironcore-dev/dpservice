# Note that these functions are not intended for production use
# Many checks are missing
# This is only to help operations to work with tcpdump on tunneled packets

ip2hex() {
	printf "0x"
	printf "%02x" ${1//./ }
}

ipip_src() {
	printf "(ip6[52:4] = $(ip2hex $1))"
}

ipip_dst() {
	printf "(ip6[56:4] = $(ip2hex $1))"
}

ipip_host() {
	printf "($(ipip_src $1) or  $(ipip_dst $1))"
}

ipip_proto() {
	printf "(ip6[49] == $1)"
}

ipip_src_udp_range() {
	printf "(ip6[49] == 17 and ip6[60:2] >= $1 and ip6[60:2] <= $2)"
}

ipip_dst_udp_range() {
	printf "(ip6[49] == 17 and ip6[62:2] >= $1 and ip6[62:2] <= $2)"
}

ipip_src_tcp_range() {
	printf "(ip6[49] == 6 and ip6[60:2] >= $1 and ip6[60:2] <= $2)"
}

ipip_dst_tcp_range() {
	printf "(ip6[49] == 6 and ip6[62:2] >= $1 and ip6[62:2] <= $2)"
}
