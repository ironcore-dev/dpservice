#include "dp_graph.h"
#include <rte_memory.h>
#include "dp_conf.h"
#include "dp_error.h"
#include "dp_log.h"
#include "dp_port.h"
#include "dp_timers.h"
#ifdef ENABLE_GRAPHTRACE
#	include "monitoring/dp_graphtrace.h"
#endif
#include "nodes/arp_node.h"
#include "nodes/dhcp_node.h"
#include "nodes/dhcpv6_node.h"
#include "nodes/ipv6_encap_node.h"
#include "nodes/ipv6_nd_node.h"
#include "nodes/l2_decap_node.h"
#include "nodes/rx_node.h"
#include "nodes/rx_periodic_node.h"
#include "nodes/tx_node.h"
#ifdef ENABLE_VIRTSVC
#	include "nodes/virtsvc_node.h"
#endif

static struct rte_graph *dp_graph;
static rte_graph_t dp_graph_id = RTE_GRAPH_ID_INVALID;
static struct rte_graph_cluster_stats *dp_graph_stats;

struct rte_graph *dp_graph_get(void)
{
	return dp_graph;
}

static inline int dp_graph_stats_create()
{
	static const char *patterns[] = { DP_GRAPH_NAME_PREFIX"*" };
	struct rte_graph_cluster_stats_param s_param = {
		.socket_id = SOCKET_ID_ANY,
		.fn = NULL,  // use the default one that prints to file handle
		.f = stdout,
		.nb_graph_patterns = 1,
		.graph_patterns = patterns,
	};

	dp_graph_stats = rte_graph_cluster_stats_create(&s_param);
	if (!dp_graph_stats) {
		DPS_LOG_ERR("Unable to create cluster stats %s", dp_strerror(rte_errno));
		return DP_ERROR;
	}

	return DP_OK;
}

static inline void dp_graph_stats_free(void)
{
	if (dp_graph_stats)
		rte_graph_cluster_stats_destroy(dp_graph_stats);
}

static void dp_graph_stats_print(__rte_unused struct rte_timer *timer, __rte_unused void *arg)
{
	static const char caret_top_left[] = {27, '[', '1', ';', '1', 'H', '\0'};
	static const char clear_screen[] = {27, '[', '2', 'J', '\0'};

	printf("%s%s", clear_screen, caret_top_left);
	// this actually prints using a function specified in dp_graph_stats_create()
	rte_graph_cluster_stats_get(dp_graph_stats, 0);
}

static int dp_graph_export(const char *graph_name)
{
	int ret;
	FILE *f;
	char fname[RTE_GRAPH_NAMESIZE + 5];  // + ".dot\0"

	if (snprintf(fname, sizeof(fname), "%s.dot", graph_name) >= sizeof(fname)) {
		DPS_LOG_ERR("Cannot export graph, name too long");
		return DP_ERROR;
	}
	f = fopen(fname, "w");
	if (!f) {
		DPS_LOG_ERR("Cannot open graph export file for writing %s", dp_strerror(errno));
		return DP_ERROR;
	}
	ret = rte_graph_export(graph_name, f);
	if (DP_FAILED(ret))
		DPS_LOG_ERR("rte_graph_export() failed %s", dp_strerror(ret));
	fclose(f);
	return ret;
}

static rte_graph_t dp_graph_create(unsigned int lcore_id)
{
	rte_graph_t graph_id;
	char graph_name[RTE_GRAPH_NAMESIZE];
	// seems that we only need to provide the source-nodes, the rest is added via connected edges
	static const char *source_node_patterns[] = { "rx-*", "rx_periodic" };
	struct rte_graph_param graph_conf = {
		.node_patterns = source_node_patterns,
		.nb_node_patterns = RTE_DIM(source_node_patterns),
		.socket_id = rte_lcore_to_socket_id(lcore_id),
	};

	snprintf(graph_name, sizeof(graph_name), DP_GRAPH_NAME_PREFIX "%u", lcore_id);

	graph_id = rte_graph_create(graph_name, &graph_conf);
	if (graph_id == RTE_GRAPH_ID_INVALID) {
		DPS_LOG_ERR("Cannot create graph for lcore %u %s", lcore_id, dp_strerror(rte_errno));
		return RTE_GRAPH_ID_INVALID;
	}
	if (DP_FAILED(dp_graph_export(graph_name)))
		return RTE_GRAPH_ID_INVALID;

	dp_graph = rte_graph_lookup(graph_name);
	if (!dp_graph) {
		DPS_LOG_ERR("Graph %s not found after creation for lcore %u", graph_name, lcore_id);
		return RTE_GRAPH_ID_INVALID;
	}

	return graph_id;
}

static int dp_graph_init_nodes()
{
	char name[RTE_NODE_NAMESIZE];
	struct dp_ports *ports = get_dp_ports();
	uint16_t port_id;

	DP_FOREACH_PORT(ports, port) {
		port_id = port->port_id;

		// need to have one Rx and one Tx node per port
		if (DP_FAILED(rx_node_create(port_id, 0))
			|| DP_FAILED(tx_node_create(port_id)))
			return DP_ERROR;

		// some nodes need a direct Tx connection to all PF/VF ports, add them dynamically
		snprintf(name, sizeof(name), "tx-%u", port->port_id);
		switch (port->port_type) {
		case DP_PORT_VF:
			if (DP_FAILED(arp_node_append_vf_tx(port_id, name))
				|| DP_FAILED(dhcp_node_append_vf_tx(port_id, name))
				|| DP_FAILED(dhcpv6_node_append_vf_tx(port_id, name))
				|| DP_FAILED(ipv6_nd_node_append_vf_tx(port_id, name))
				|| DP_FAILED(l2_decap_node_append_vf_tx(port_id, name))
				|| DP_FAILED(rx_periodic_node_append_vf_tx(port_id, name)))
				return DP_ERROR;
			break;
		case DP_PORT_PF:
			if (DP_FAILED(ipv6_encap_node_append_pf_tx(port_id, name)))
				return DP_ERROR;
			break;
		}
#ifdef ENABLE_VIRTSVC
		// virtual services node is bi-directional
		if (DP_FAILED(virtsvc_node_append_tx(port_id, name)))
			return DP_ERROR;
#endif
	}
	return DP_OK;
}

int dp_graph_init(void)
{
	// currently limited to only one graph (and first core is reserved for the main loop)
	if (rte_lcore_count() != 2) {
		DPS_LOG_ERR("Too many worker cores requested (%d), max 2", rte_lcore_count());
		return DP_ERROR;
	}
#ifdef ENABLE_GRAPHTRACE
	if (DP_FAILED(dp_graphtrace_init()))
		return DP_ERROR;
#endif
	if (DP_FAILED(dp_graph_init_nodes()))
		return DP_ERROR;

	// find the right core(s) to run on
	// start from second core, first core is for main loop, not graph
	for (unsigned int lcore_id = 1; lcore_id < RTE_MAX_LCORE; ++lcore_id) {
		if (!rte_lcore_is_enabled(lcore_id))
			continue;
		dp_graph_id = dp_graph_create(lcore_id);
		if (dp_graph_id == RTE_GRAPH_ID_INVALID)
			return DP_ERROR;
		// only one graph worker allowed atm.
		break;
	}

	// only now stats can be enabled as the graph(s) must already exist
	if (dp_conf_is_stats_enabled()) {
		if (!rte_graph_has_stats_feature()) {
			DPS_LOG_WARNING("Graph statistics are not available");
		} else if (DP_FAILED(dp_graph_stats_create())
			|| DP_FAILED(dp_timers_add_stats(dp_graph_stats_print))
		) {
			rte_graph_destroy(dp_graph_id);
			return DP_ERROR;
		}
	}

	return DP_OK;
}

void dp_graph_free(void)
{
	dp_graph_stats_free();
	if (dp_graph_id != RTE_GRAPH_ID_INVALID)
		rte_graph_destroy(dp_graph_id);
#ifdef ENABLE_GRAPHTRACE
	dp_graphtrace_free();
#endif
}
