// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

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

struct dp_telemetry_htable {
	const struct rte_hash *htable;
	int capacity;
	char name[RTE_HASH_NAMESIZE];
};

static struct dp_telemetry_htable *tel_htables = NULL;
static int tel_htable_count = 0;

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
static __rte_always_inline uint64_t get_stat_value(const struct rte_graph_cluster_node_stats *st)
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
		if (DP_FAILED(tel_callback_ret)) {
			rte_tel_data_free(tel_curr_block);
			return tel_callback_ret;
		}

		snprintf(dict_name, sizeof(dict_name), "Node_%hd_to_%hd",
				(uint16_t)(tel_graph_node_index-1), (uint16_t)(tel_graph_node_index + (RTE_TEL_MAX_DICT_ENTRIES-2)));
		tel_callback_ret = rte_tel_data_add_dict_container(tel_data, dict_name, tel_curr_block, 0);
		if (DP_FAILED(tel_callback_ret)) {
			rte_tel_data_free(tel_curr_block);
			return tel_callback_ret;
		}
	}

	tel_callback_ret = rte_tel_data_add_dict_uint(tel_curr_block, stats->name, get_stat_value(stats));
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
	if (DP_FAILED(dp_telemetry_start_dict(data, cmd))
		|| DP_FAILED(dp_nat_get_used_ports_telemetry(data)))
		return DP_ERROR;
	return DP_OK;
}


static int dp_telemetry_add_htable(struct rte_tel_data *parent,
								   struct rte_tel_data *data,
								   const struct dp_telemetry_htable *htable)
{
	int ret;

	ret = rte_tel_data_start_dict(data);
	if (DP_FAILED(ret))
		return ret;

	ret = rte_tel_data_add_dict_u64(data, "capacity", htable->capacity);
	if (DP_FAILED(ret))
		return ret;

	ret = rte_tel_data_add_dict_u64(data, "entries", rte_hash_count(htable->htable));
	if (DP_FAILED(ret))
		return ret;

	ret = rte_tel_data_add_dict_container(parent, htable->name, data, 0);
	if (DP_FAILED(ret))
		return ret;

	return DP_OK;
}

static int dp_telemetry_handle_table_saturation(const char *cmd,
												__rte_unused const char *params,
												struct rte_tel_data *data)
{
	struct rte_tel_data *htable_data;

	if (DP_FAILED(dp_telemetry_start_dict(data, cmd)))
		return DP_ERROR;

	for (int i = 0; i < tel_htable_count; ++i) {
		htable_data = rte_tel_data_alloc();
		if (!htable_data)
			return DP_ERROR;
		if (DP_FAILED(dp_telemetry_add_htable(data, htable_data, &tel_htables[i]))) {
			rte_tel_data_free(htable_data);
			return DP_ERROR;
		}
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
		DP_TELEMETRY_REGISTER_COMMAND(table, saturation, "Returns the current and maximal capacity of each hash table."),
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

	for (size_t i = 0; i < RTE_DIM(commands); ++i) {
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
	free(tel_htables);
	if (rte_graph_has_stats_feature())
		dp_telemetry_graph_stats_destroy();
}

int dp_telemetry_register_htable(const struct rte_hash *htable, const char name[RTE_HASH_NAMESIZE], int capacity)
{
	struct dp_telemetry_htable *entry;
	void *tmp;

	if (tel_htable_count >= RTE_TEL_MAX_DICT_ENTRIES) {
		DPS_LOG_ERR("Telemetry hashtable registry is full");
		return DP_ERROR;
	}

	tmp = realloc(tel_htables, (tel_htable_count + 1) * sizeof(*entry));
	if (!tmp) {
		DPS_LOG_ERR("Cannot allocate telemetry hashtable registry entry");
		return DP_ERROR;
	}

	tel_htables = tmp;
	entry = &tel_htables[tel_htable_count++];
	entry->htable = htable;
	entry->capacity = capacity;
	snprintf(entry->name, sizeof(entry->name), "%s", name);
	return DP_OK;
}
