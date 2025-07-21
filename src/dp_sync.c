#include "dp_sync.h"

#include "dp_error.h"


int dp_sync_create_nat(const struct netnat_portmap_key *portmap_key,
					   const struct netnat_portoverload_tbl_key *portoverload_key)
{
	DPS_LOG_ERR("CREATE NAT",
				_DP_LOG_INT("src_vni", portmap_key->vni),
				_DP_LOG_IPV4("src_ip", portmap_key->src_ip.ipv4), // TODO yes, NAT64 (already soved by the struct)
				_DP_LOG_INT("src_port", portmap_key->iface_src_port),
				_DP_LOG_IPV4("nat_ip",  portoverload_key->nat_ip),
				_DP_LOG_INT("nat_port", portoverload_key->nat_port),
				_DP_LOG_IPV4("dst_ip", portoverload_key->dst_ip),
				_DP_LOG_INT("dst_port", portoverload_key->dst_port),
				_DP_LOG_INT("proto", portoverload_key->l4_type));
	return DP_OK;
}


int dp_sync_delete_nat(const struct netnat_portmap_key *portmap_key,
					   const struct netnat_portoverload_tbl_key *portoverload_key)
{
	DPS_LOG_ERR("REMOVE NAT",
				_DP_LOG_INT("src_vni", portmap_key->vni),
				_DP_LOG_IPV4("src_ip", portmap_key->src_ip.ipv4), // TODO yes, NAT64 (already soved by the struct)
				_DP_LOG_INT("src_port", portmap_key->iface_src_port),
				_DP_LOG_IPV4("nat_ip",  portoverload_key->nat_ip),
				_DP_LOG_INT("nat_port", portoverload_key->nat_port),
				_DP_LOG_IPV4("dst_ip", portoverload_key->dst_ip),
				_DP_LOG_INT("dst_port", portoverload_key->dst_port),
				_DP_LOG_INT("proto", portoverload_key->l4_type));
	return DP_OK;
}
