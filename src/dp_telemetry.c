#include "dp_telemetry.h"

#include <rte_telemetry.h>
#include <stdbool.h>
#include <string.h>

#include "dp_error.h"
#include "dp_graph.h"
#include "dp_log.h"
#ifdef ENABLE_VIRTSVC
#	include "dp_virtsvc.h"
#endif
#include "dpdk_layer.h"
#include "dp_internal_stats.h"


static struct rte_graph_cluster_stats *tel_stats;
static int32_t tel_graph_node_index = 0;
static struct rte_tel_data *tel_data = NULL;
static struct rte_tel_data *tel_curr_block =  NULL;
static int tel_callback_ret = 0;
static int tel_stat_value_offset = 0;

// as a dictionary only supports 256 entries, two-levels can only contain 65536 entries total
#define DP_NODE_BLOCK_NAME_MAX sizeof("Node_65279_to_65535")

#define DP_TELEMETRY_PREFIX "/dp_service"

// Since telemetry has no argument for the callback, macros to generate separate callbacks are used instead
#define DP_TELEMETRY_REGISTER_COMMAND(GROUP, NAME, DESCRIPTION) \
	{ DP_TELEMETRY_PREFIX "/" #GROUP "/" #NAME, DESCRIPTION, dp_telemetry_handle_ ## GROUP ## _ ## NAME }

// All graph callbacks are the same, just need a different stats structure member
#define DP_TELEMETRY_CREATE_GRAPH_HANDLER(NAME, MEMBER) \
	static int dp_telemetry_handle_graph_##NAME(__rte_unused const char *cmd, \
												__rte_unused const char *params, \
												struct rte_tel_data *data) \
	{ \
		tel_stat_value_offset = offsetof(struct rte_graph_cluster_node_stats, MEMBER); \
		return dp_telemetry_handle_graph_command(data); \
	}

//
// Graph introduces another layer of callbacks due to DPDK stats API
//
static __rte_always_inline int get_stat_value(const struct rte_graph_cluster_node_stats *st)
{
	return *(const uint64_t *)((const uint8_t *)(st) + tel_stat_value_offset);
}

static int dp_telemetry_graph_stats_cb(__rte_unused bool is_first,
									   __rte_unused bool is_last,
									   __rte_unused void *cookie,
									   const struct rte_graph_cluster_node_stats *stats)
{
	char dict_name[DP_NODE_BLOCK_NAME_MAX];

	if (!stats)
		return DP_OK;

	if (tel_graph_node_index >= (RTE_TEL_MAX_DICT_ENTRIES * RTE_TEL_MAX_DICT_ENTRIES)) {
		tel_callback_ret = -ENOSPC;
		return tel_callback_ret;
	}

	if (tel_graph_node_index++ % RTE_TEL_MAX_DICT_ENTRIES == 0) {
		tel_curr_block = rte_tel_data_alloc();
		if (!tel_curr_block) {
			tel_callback_ret = -ENOMEM;
			return tel_callback_ret;
		}
		tel_callback_ret = rte_tel_data_start_dict(tel_curr_block);
		if (DP_FAILED(tel_callback_ret))
			return tel_callback_ret;
		snprintf(dict_name, sizeof(dict_name), "Node_%d_to_%d",
				tel_graph_node_index-1, tel_graph_node_index + (RTE_TEL_MAX_DICT_ENTRIES-2));
		tel_callback_ret = rte_tel_data_add_dict_container(tel_data, dict_name, tel_curr_block, 0);
		if (DP_FAILED(tel_callback_ret))
			return tel_callback_ret;
	}

	tel_callback_ret = rte_tel_data_add_dict_u64(tel_curr_block, stats->name, get_stat_value(stats));
	if (DP_FAILED(tel_callback_ret))
		return tel_callback_ret;

	return DP_OK;
}

static int dp_telemetry_graph_stats_create(void)
{
	static const char *patterns[] = { DP_GRAPH_NAME_PREFIX"*" };
	struct rte_graph_cluster_stats_param s_param = {
		.socket_id = SOCKET_ID_ANY,
		.fn = dp_telemetry_graph_stats_cb,
		.nb_graph_patterns = 1,
		.graph_patterns = patterns,
	};

	tel_stats = rte_graph_cluster_stats_create(&s_param);
	if (!tel_stats) {
		DPS_LOG_ERR("Unable to create cluster stats", DP_LOG_RET(rte_errno));
		return DP_ERROR;
	}
	return DP_OK;
}

static void dp_telemetry_graph_stats_destroy(void)
{
	rte_graph_cluster_stats_destroy(tel_stats);
}

//
// Command handler callbacks
//
static inline int dp_telemetry_start_dict(struct rte_tel_data *data, const char *cmd)
{
	int ret;

	ret = rte_tel_data_start_dict(data);
	if (DP_FAILED(ret))
		DPS_LOG_WARNING("Creating telemetry dictionary failed", DP_LOG_TELEMETRY_CMD(cmd), DP_LOG_RET(ret));

	return ret;
}

static int dp_telemetry_handle_graph_command(struct rte_tel_data *data)
{
	if (DP_FAILED(dp_telemetry_start_dict(data, "graph statistics")))
		return DP_ERROR;

	// no graph stats feature?
	if (!tel_stats)
		return DP_OK;

	tel_data = data;
	tel_callback_ret = 0;
	tel_graph_node_index = 0;
	rte_graph_cluster_stats_get(tel_stats, 0);
	if (DP_FAILED(tel_callback_ret))
		DPS_LOG_WARNING("Graph telemetry failed", DP_LOG_RET(tel_callback_ret));
	return tel_callback_ret;
}
DP_TELEMETRY_CREATE_GRAPH_HANDLER(obj_count, objs)
DP_TELEMETRY_CREATE_GRAPH_HANDLER(call_count, calls)
DP_TELEMETRY_CREATE_GRAPH_HANDLER(cycle_count, cycles)
DP_TELEMETRY_CREATE_GRAPH_HANDLER(realloc_count, realloc_count)

#ifdef ENABLE_VIRTSVC
static int dp_telemetry_handle_virtsvc_used_port_count(const char *cmd,
												  __rte_unused const char *params,
												  struct rte_tel_data *data)
{
	if (DP_FAILED(dp_telemetry_start_dict(data, cmd))
		|| DP_FAILED(dp_virtsvc_get_used_ports_telemetry(data)))
		return DP_ERROR;
	return DP_OK;
}
#endif

static int dp_telemetry_handle_nat_used_port_count(const char *cmd,
												  __rte_unused const char *params,
												  struct rte_tel_data *data)
{

	int ret;

	ret = dp_telemetry_start_dict(data, cmd);
	if (DP_FAILED(ret)) {
		DPS_LOG_WARNING("Failed to init telemetry data to get interface's used nat port cnt",
						DP_LOG_TELEMETRY_CMD(cmd), DP_LOG_RET(ret));
		return DP_ERROR;
	}

	ret = dp_nat_get_used_ports_telemetry(data);
	if (DP_FAILED(ret)) {
		DPS_LOG_WARNING("Failed to get used nat ports' telemetry data",
						DP_LOG_TELEMETRY_CMD(cmd), DP_LOG_RET(ret));
		return DP_ERROR;
	}

	return DP_OK;

}

//
// Entrypoints
//
int dp_telemetry_init(void)
{
	int ret;

	static const struct {
		const char *command;
		const char *description;
		telemetry_cb callback;
	} commands[] = {
		DP_TELEMETRY_REGISTER_COMMAND(graph, obj_count, "Returns total number of objects processed by each graph node."),
		DP_TELEMETRY_REGISTER_COMMAND(graph, call_count, "Returns total number of calls made by each graph node."),
		DP_TELEMETRY_REGISTER_COMMAND(graph, cycle_count, "Returns total number of cycles used by each graph node."),
		DP_TELEMETRY_REGISTER_COMMAND(graph, realloc_count, "Returns total number of reallocations done by each graph node."),
		DP_TELEMETRY_REGISTER_COMMAND(nat, used_port_count, "Returns the number of nat ports in use by each VF interface (attached VM)."),
#ifdef ENABLE_VIRTSVC
		DP_TELEMETRY_REGISTER_COMMAND(virtsvc, used_port_count, "Returns the number of ports in use by each virtual service."),
#endif
	};

	if (!rte_graph_has_stats_feature())
		DPS_LOG_WARNING("DPDK graph stats not enabled, graph telemetry will not work.");
	else if (DP_FAILED(dp_telemetry_graph_stats_create()))
		return DP_ERROR;

#ifdef ENABLE_VIRTSVC
	// make sure one dictionary is enough
	// (the number should be limited already for other reasons anyway)
	if (dp_virtsvc_get_count() > RTE_TEL_MAX_DICT_ENTRIES) {
		DPS_LOG_ERR("Too many virtual services for telemetry to work", DP_LOG_MAX(RTE_TEL_MAX_DICT_ENTRIES));
		return DP_ERROR;
	}
#endif

	for (uint i = 0; i < RTE_DIM(commands); ++i) {
		ret = rte_telemetry_register_cmd(commands[i].command, commands[i].callback, commands[i].description);
		if (DP_FAILED(ret)) {
			DPS_LOG_ERR("Failed to register telemetry command", DP_LOG_TELEMETRY_CMD(commands[i].command), DP_LOG_RET(ret));
			return ret;
		}
	}
	return DP_OK;
}

void dp_telemetry_free(void)
{
	if (rte_graph_has_stats_feature())
		dp_telemetry_graph_stats_destroy();
}
