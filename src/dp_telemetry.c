#include "dp_telemetry.h"

#include <stdbool.h>
#include <string.h>
#include <rte_telemetry.h>

#include "dp_log.h"
#include "dp_error.h"
#include "dpdk_layer.h"

static struct rte_graph_cluster_stats *tel_stats;
static int32_t tel_graph_node_index = 0;
static struct rte_tel_data *tel_data = NULL;
static struct rte_tel_data *tel_curr_block =  NULL;
static int tel_callback_ret = 0;
static int tel_stat_value_offset = 0;

// as a dictionary only supports 256 entries, two-levels can only contain 65536 entries total
#define NODE_BLOCK_NAME_MAX sizeof("Node_65279_to_65535")

#define DP_TELEMETRY_PREFIX "/dp_service/"
#define DP_TELEMETRY_GRAPH_PREFIX DP_TELEMETRY_PREFIX "graph/"

static __rte_always_inline int get_stat_value(const struct rte_graph_cluster_node_stats *st)
{
	return (*(uint64_t *)((uint8_t *)(st) + tel_stat_value_offset));
}

static int dp_telemetry_graph_stats_cb(__rte_unused bool is_first,
									   __rte_unused bool is_last,
									   __rte_unused void *cookie,
									   const struct rte_graph_cluster_node_stats *stats)
{
	char dict_name[NODE_BLOCK_NAME_MAX];

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
		rte_tel_data_start_dict(tel_curr_block);
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

static int dp_telemetry_graph_stats_create()
{
	// TODO: use pattern in dp_graph.h (PR pending)
	const char *pattern = "worker_*";
	struct rte_graph_cluster_stats_param s_param = {
		.socket_id = SOCKET_ID_ANY,
		.fn = dp_telemetry_graph_stats_cb,
		.nb_graph_patterns = 1,
		.graph_patterns = &pattern,
	};

	tel_stats = rte_graph_cluster_stats_create(&s_param);
	if (!tel_stats) {
		DPS_LOG_ERR("Unable to create cluster stats %s", dp_strerror(rte_errno));
		return DP_ERROR;
	}
	return DP_OK;
}

static void dp_telemetry_graph_stats_destroy()
{
	rte_graph_cluster_stats_destroy(tel_stats);
}

int dp_telemetry_graph_init()
{
	if (!rte_graph_has_stats_feature()) {
		DPS_LOG_WARNING("DPDK graph stats not enabled, telemetry will not work.");
		return DP_OK;
	}
	return (dp_telemetry_graph_stats_create());
}

static void dp_telemetry_handle_graph_command(struct rte_tel_data *data)
{
	tel_data = data;
	tel_callback_ret = 0;
	tel_graph_node_index = 0;
	rte_tel_data_start_dict(tel_data);
	rte_graph_cluster_stats_get(tel_stats, 0);
	if (DP_FAILED(tel_callback_ret))
		DPS_LOG_WARNING("Graph telemetry failed %s", dp_strerror(tel_callback_ret));
}

// All graph callbacks are the same, just need a different stats structure member
#define TEL_GRAPH_COMMAND_HANDLER(NAME, MEMBER) \
	static int dp_telemetry_handle_graph_##NAME(__rte_unused const char *cmd, \
												const char *params, \
												struct rte_tel_data *data) \
	{ \
		tel_stat_value_offset = offsetof(struct rte_graph_cluster_node_stats, MEMBER); \
		dp_telemetry_handle_graph_command(data); \
		return DP_OK; \
	}
TEL_GRAPH_COMMAND_HANDLER(obj_count, objs);
TEL_GRAPH_COMMAND_HANDLER(call_count, calls);
TEL_GRAPH_COMMAND_HANDLER(cycle_count, cycles);
TEL_GRAPH_COMMAND_HANDLER(realloc_count, realloc_count);

int dp_telemetry_init(void)
{
	int ret;

#define TEL_GRAPH_COMMAND(NAME, DESCRIPTION) { DP_TELEMETRY_GRAPH_PREFIX #NAME, DESCRIPTION, dp_telemetry_handle_graph_##NAME }
	static const struct {
		const char *command;
		const char *description;
		telemetry_cb callback;
	} commands[] = {
		TEL_GRAPH_COMMAND(obj_count, "Returns total number of objects processed by each graph node."),
		TEL_GRAPH_COMMAND(call_count, "Returns total number of calls made by each graph node."),
		TEL_GRAPH_COMMAND(cycle_count, "Returns total number of cycles used by each graph node."),
		TEL_GRAPH_COMMAND(realloc_count, "Returns total number of reallocations done by each graph node."),
	};

	for (int i = 0; i < RTE_DIM(commands); ++i) {
		ret = rte_telemetry_register_cmd(commands[i].command, commands[i].callback, commands[i].description);
		if (DP_FAILED(ret)) {
			DPS_LOG_ERR("Failed to register telemetry command %s:%s", commands[i].command, dp_strerror(ret));
			return ret;
		}
	}
	return DP_OK;
}

void dp_telemetry_free(void)
{
	dp_telemetry_graph_stats_destroy();
}
