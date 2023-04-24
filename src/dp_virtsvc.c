#include "dp_virtsvc.h"

#include <stdlib.h>
#include <rte_cycles.h>
#include <rte_malloc.h>

#include "dp_conf.h"
#include "dp_error.h"
#include "dp_flow.h"
#include "dp_log.h"
#include "dp_multi_path.h"
#include "dp_util.h"
#include "rte_flow/dp_rte_flow_init.h"

// WARNING: This module is not designed to be thread-safe (even though it could work)
// It is assumed that thread-unsafe code will only ever be called from one node
// and that such node will only be bound to one thread.

#define DP_VIRTSVC_TELEMETRY_MAX_NAME_SIZE sizeof("TCP:255.255.255.255:65535")

#define DP_VIRTSVC_PRINT_FMT "%s virtual service " DP_IPV4_PRINT_FMT ":%u <-> " DP_IPV6_PRINT_FMT ":%u"
#define DP_VIRTSVC_PRINT_ARGS(SERVICE) \
	(SERVICE)->proto == IPPROTO_TCP ? "TCP" : "UDP", \
	DP_IPV4_PRINT_BYTES((SERVICE)->virtual_addr), (SERVICE)->virtual_port, \
	DP_IPV6_PRINT_BYTES((SERVICE)->service_addr), (SERVICE)->service_port

#pragma pack(push, 1)
// packed, because hashing would include padding otherwise
struct dp_virtsvc_conn_key {
	uint16_t vf_port_id;
	rte_be16_t vf_l4_port;
};
#pragma pack(pop)

static struct dp_virtsvc *dp_virtservices;
static struct dp_virtsvc *dp_virtservices_end;

#define DP_FOREACH_VIRTSVC(SERVICES, VARNAME) \
	for (struct dp_virtsvc *VARNAME = dp_virtservices; \
		 (VARNAME) < dp_virtservices_end; \
		 ++VARNAME)

static uint64_t port_timeout = DP_FLOW_DEFAULT_TIMEOUT;
static uint64_t established_port_timeout = DP_FLOW_TCP_EXTENDED_TIMEOUT;
#ifdef ENABLE_PYTEST
static bool fast_timeout = false;
#endif

static struct dp_virtsvc_lookup_entry *dp_virtsvc_ipv4_tree = NULL;
static struct dp_virtsvc_lookup_entry *dp_virtsvc_ipv6_tree = NULL;

const struct dp_virtsvc_lookup_entry *dp_virtsvc_get_ipv4_tree()
{
	return dp_virtsvc_ipv4_tree;
}

const struct dp_virtsvc_lookup_entry *dp_virtsvc_get_ipv6_tree()
{
	return dp_virtsvc_ipv6_tree;
}

static int dp_virtsvc_array_to_tree(struct dp_virtsvc_lookup_entry **dst, struct dp_virtsvc **array, int start, int end)
{
	struct dp_virtsvc_lookup_entry *entry;
	int mid;

	*dst = NULL;

	if (start > end)
		return DP_OK;

	entry = (struct dp_virtsvc_lookup_entry *)malloc(sizeof(struct dp_virtsvc_lookup_entry));
	if (!entry)
		return DP_ERROR;

	mid = (start + end) / 2;
	entry->virtsvc = array[mid];

	if (DP_FAILED(dp_virtsvc_array_to_tree(&entry->left, array, start, mid-1))
		|| DP_FAILED(dp_virtsvc_array_to_tree(&entry->right, array, mid+1, end)))
		return DP_ERROR;

	*dst = entry;
	return DP_OK;
}

static int dp_virtsvc_ipv4_comparator(const void *p1, const void *p2)
{
	const struct dp_virtsvc *l = *(const struct dp_virtsvc **)p1;
	const struct dp_virtsvc *r = *(const struct dp_virtsvc **)p2;

	return dp_virtsvc_ipv4_cmp(l->proto, l->virtual_addr, l->virtual_port,
							   r->proto, r->virtual_addr, r->virtual_port);
}

static int dp_virtsvc_ipv6_comparator(const void *p1, const void *p2)
{
	const struct dp_virtsvc *l = *(const struct dp_virtsvc **)p1;
	const struct dp_virtsvc *r = *(const struct dp_virtsvc **)p2;

	return dp_virtsvc_ipv6_cmp(l->proto, l->service_addr, l->service_port,
							   r->proto, r->service_addr, r->service_port);
}

static int dp_virtsvc_create_trees()
{
	int service_count = dp_virtsvc_get_count();
	struct dp_virtsvc **array;

	if (service_count <= 0)
		return DP_ERROR;

	// create an array of virtsvc pointers, sort it by IPv4, and create a balanced binary search tree from it
	array = (struct dp_virtsvc **)malloc(sizeof(struct dp_virtsvc *) * service_count);
	if (!array)
		return DP_ERROR;

	for (int i = 0; i < service_count; ++i)
		array[i] = &dp_virtservices[i];

	qsort(array, service_count, sizeof(struct dp_virtsvc *), dp_virtsvc_ipv4_comparator);

	if (DP_FAILED(dp_virtsvc_array_to_tree(&dp_virtsvc_ipv4_tree, array, 0, service_count-1))) {
		free(array);
		return DP_ERROR;
	}

	// re-sort by IPv6 and create the other tree
	qsort(array, service_count, sizeof(struct dp_virtsvc *), dp_virtsvc_ipv6_comparator);

	if (DP_FAILED(dp_virtsvc_array_to_tree(&dp_virtsvc_ipv6_tree, array, 0, service_count-1))) {
		free(array);
		return DP_ERROR;
	}

	free(array);
	return DP_OK;
}

int dp_virtsvc_init(int socket_id)
{
	const struct dp_conf_virtual_services *rules = dp_conf_get_virtual_services();
	struct dp_conf_virtsvc *rule;
	char hashtable_name[32];  // max is 'virtsvc_table_4294967295'

	if (!rules->nb_entries)
		return DP_OK;

	dp_virtservices = (struct dp_virtsvc *)rte_zmalloc("virtual_services",
															sizeof(struct dp_virtsvc) * rules->nb_entries,
															RTE_CACHE_LINE_SIZE);
	if (!dp_virtservices) {
		DPS_LOG_ERR("Cannot allocate virtual services table");
		return DP_ERROR;
	}

	dp_virtservices_end = dp_virtservices;
	for (int i = 0; i < rules->nb_entries; ++i) {
		rule = &rules->entries[i];
		dp_virtservices_end->proto = rule->proto;
		dp_virtservices_end->virtual_addr = rule->virtual_addr;
		dp_virtservices_end->virtual_port = rule->virtual_port;
		dp_virtservices_end->service_port = rule->service_port;
		rte_memcpy(dp_virtservices_end->service_addr, rule->service_addr, sizeof(rule->service_addr));
		// last_assigned_port is 0 due to zmalloc()
		snprintf(hashtable_name, sizeof(hashtable_name), "virtsvc_table_%u", i);
		dp_virtservices_end->open_ports = dp_create_jhash_table(DP_VIRTSVC_PORTCOUNT,
																sizeof(struct dp_virtsvc_conn_key),
																hashtable_name,
																socket_id);
		if (!dp_virtservices_end->open_ports) {
			DPS_LOG_ERR("Cannot allocate connection table #%u", i);
			dp_virtsvc_free();
			return DP_ERROR;
		}
		dp_virtservices_end++;
	}

	if (DP_FAILED(dp_virtsvc_create_trees())) {
		DPS_LOG_ERR("Failed to build lookup trees");
		dp_virtsvc_free();
		return DP_ERROR;
	}

#ifdef ENABLE_PYTEST
	port_timeout = dp_conf_get_flow_timeout();
	fast_timeout = port_timeout != DP_FLOW_DEFAULT_TIMEOUT;
#endif
	port_timeout *= rte_get_timer_hz();
	established_port_timeout *= rte_get_timer_hz();

	return DP_OK;
}

static void dp_virtsvc_free_tree(struct dp_virtsvc_lookup_entry *tree)
{
	if (!tree)
		return;
	dp_virtsvc_free_tree(tree->left);
	dp_virtsvc_free_tree(tree->right);
	free(tree);
}

void dp_virtsvc_free()
{
	dp_virtsvc_free_tree(dp_virtsvc_ipv4_tree);
	dp_virtsvc_free_tree(dp_virtsvc_ipv6_tree);
	DP_FOREACH_VIRTSVC(&dp_virtservices, service)
		dp_free_jhash_table(service->open_ports);
	rte_free(dp_virtservices);
}

int dp_virtsvc_get_count()
{
	return dp_virtservices_end - dp_virtservices;
}


int dp_virtsvc_install_isolation_rules(uint16_t port_id)
{
	DP_FOREACH_VIRTSVC(&dp_virtservices, service) {
		if (DP_FAILED(dp_install_isolated_mode_virtsvc(port_id,
													   service->proto,
													   service->service_addr,
													   service->service_port))
		) {
			DPS_LOG_ERR("Cannot create isolation rule for " DP_VIRTSVC_PRINT_FMT, DP_VIRTSVC_PRINT_ARGS(service));
			return DP_ERROR;
		}
	}
	return DP_OK;
}


static __rte_always_inline bool dp_virtsvc_is_connection_old(struct dp_virtsvc_conn *conn, uint64_t current_tsc)
{
	uint64_t timeout = conn->last_pkt_timestamp + (conn->state == DP_VIRTSVC_CONN_ESTABLISHED
														? established_port_timeout
														: port_timeout);

	return current_tsc > timeout;
}

static __rte_always_inline int dp_virtsvc_get_free_port(struct dp_virtsvc *virtsvc)
{
	uint64_t current_tsc = rte_get_timer_cycles();

#ifdef ENABLE_PYTEST
	// flow timeout is being tested, try to revisit already used ports
	if (fast_timeout)
		virtsvc->last_assigned_port = 0;
#endif

	for (int port = virtsvc->last_assigned_port+1; port < DP_VIRTSVC_PORTCOUNT; ++port)
		if (dp_virtsvc_is_connection_old(&virtsvc->connections[port], current_tsc))
			return virtsvc->last_assigned_port = port;

	for (int port = 0; port <= virtsvc->last_assigned_port; ++port)
		if (dp_virtsvc_is_connection_old(&virtsvc->connections[port], current_tsc))
			return virtsvc->last_assigned_port = port;

	DPS_LOG_WARNING(DP_VIRTSVC_PRINT_FMT " ran out of ports", DP_VIRTSVC_PRINT_ARGS(virtsvc));
	return DP_ERROR;
}

static __rte_always_inline int dp_virtsvc_create_connection(struct dp_virtsvc *virtsvc,
															struct dp_virtsvc_conn_key *key,
															hash_sig_t sig,
															rte_be32_t vf_ip)
{
	struct dp_virtsvc_conn_key delete_key;
	struct dp_virtsvc_conn *conn;
	uint16_t free_port;
	int ret;

	ret = dp_virtsvc_get_free_port(virtsvc);
	if (DP_FAILED(ret))
		return ret;

	free_port = (uint16_t)ret;
	conn = &virtsvc->connections[free_port];

	if (conn->last_pkt_timestamp) {
		delete_key.vf_port_id = conn->vf_port_id;
		delete_key.vf_l4_port = conn->vf_l4_port;
		ret = rte_hash_del_key(virtsvc->open_ports, &delete_key);
		if (DP_FAILED(ret))
			DPS_LOG_WARNING("Cannot delete virtual serice NAT entry %s", dp_strerror(ret));
	}

	ret = rte_hash_add_key_with_hash_data(virtsvc->open_ports, key, sig, (void *)(intptr_t)free_port);
	if (DP_FAILED(ret))
		return ret;

	conn->vf_ip = vf_ip;
	conn->vf_l4_port = key->vf_l4_port;
	conn->vf_port_id = key->vf_port_id;
	conn->state = DP_VIRTSVC_CONN_TRANSIENT;

	return free_port;
}

static __rte_always_inline int dp_virstvc_get_connection(struct dp_virtsvc *virtsvc,
														 struct dp_virtsvc_conn_key *key,
														 hash_sig_t sig)
{
	void *data;
	int ret;

	ret = rte_hash_lookup_with_hash_data(virtsvc->open_ports, key, sig, &data);
	if (DP_FAILED(ret))
		return ret;

	assert((intptr_t)data >= 0 && (intptr_t)data < DP_VIRTSVC_PORTCOUNT);
	return (intptr_t)data;
}

int dp_virtsvc_get_pf_route(struct dp_virtsvc *virtsvc,
							 uint16_t vf_port_id,
							 rte_be32_t vf_ip,
							 rte_be16_t vf_l4_port,
							 uint16_t *pf_port_id,
							 int *conn_idx)
{
	struct dp_virtsvc_conn_key key = {
		.vf_port_id = vf_port_id,
		.vf_l4_port = vf_l4_port
	};
	hash_sig_t key_hash = rte_hash_hash(virtsvc->open_ports, &key);
	int ret;

	ret = dp_virstvc_get_connection(virtsvc, &key, key_hash);
	if (ret == -ENOENT)
		ret = dp_virtsvc_create_connection(virtsvc, &key, key_hash, vf_ip);
	if (DP_FAILED(ret)) {
		DPS_LOG_WARNING("Cannot create connection for " DP_VIRTSVC_PRINT_FMT " %s",
						DP_VIRTSVC_PRINT_ARGS(virtsvc), dp_strerror(ret));
		return ret;
	}

	*conn_idx = ret;

	_Static_assert(sizeof(key_hash) == sizeof(uint32_t));
	*pf_port_id = dp_multipath_get_pf(key_hash);

	return DP_OK;
}


void dp_virtsvc_del_vm(uint16_t port_id)
{
	struct dp_virtsvc_conn_key delete_key;
	struct dp_virtsvc_conn *conn;
	int ret;

	DP_FOREACH_VIRTSVC(&dp_virtservices, service) {
		// This seems sub-optimal as it always checks *all* ports.
		// But in practice, the port table is always full anyway
		// as timed-out connections get replaced with new ones on-demand
		// (i.e. the table is constantly full after the first 64k connections)
		for (int i = 0; i < RTE_DIM(service->connections); ++i) {
			conn = &service->connections[i];
			if (conn->vf_port_id == port_id) {
				conn->last_pkt_timestamp = 0;
				delete_key.vf_port_id = conn->vf_port_id;
				delete_key.vf_l4_port = conn->vf_l4_port;
				ret = rte_hash_del_key(service->open_ports, &delete_key);
				if (DP_FAILED(ret))
					DPS_LOG_WARNING("Cannot delete virtual serice NAT entry for port %u %s", port_id, dp_strerror(ret));
			}
		}
	}
}

static inline uint64_t dp_virtsvc_get_free_port_count(struct dp_virtsvc *virtsvc)
{
	uint64_t free_ports = 0;
	uint64_t current_tsc = rte_get_timer_cycles();

	for (int port = 0; port < DP_VIRTSVC_PORTCOUNT; ++port) {
		if (dp_virtsvc_is_connection_old(&virtsvc->connections[port], current_tsc))
		++free_ports;
	}
	return free_ports;
}

int dp_virtsvc_get_free_ports_telemetry(struct rte_tel_data *dict)
{
	int ret;
	char virtsvc_name[DP_VIRTSVC_TELEMETRY_MAX_NAME_SIZE];

	DP_FOREACH_VIRTSVC(&dp_virtservices, service) {
		snprintf(virtsvc_name, sizeof(virtsvc_name),
				 "%s:" DP_IPV4_PRINT_FMT ":%u",
				 service->proto == IPPROTO_TCP ? "TCP" : "UDP",
				 DP_IPV4_PRINT_BYTES(service->virtual_addr),
				 ntohs(service->virtual_port));
		ret = rte_tel_data_add_dict_u64(dict, virtsvc_name, dp_virtsvc_get_free_port_count(service));
		if (DP_FAILED(ret)) {
			DPS_LOG_ERR("Failed to add virtsvc telemetry data %s", dp_strerror(ret));
			return ret;
		}
	}
	return DP_OK;
}
