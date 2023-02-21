#include "rte_telemetry.h"
#include "stdbool.h"
#include "dp_telemetry.h"
#include "string.h"
#include "rte_memory.h"
#include "dp_log.h"
#include "dp_error.h"


static struct graph_node_stat *stat_table;
extern struct rte_graph_cluster_stats *telemetry_stats;
extern rte_node_t nb_nodes;
static uint64_t node_index = 0;

int dp_stats_cb(bool is_first, bool is_last, void *cookie,
		const struct rte_graph_cluster_node_stats *st)
{
	RTE_SET_USED(is_first);
	RTE_SET_USED(is_last);
	RTE_SET_USED(cookie); 
	if (st && node_index < nb_nodes) {
		strcpy(stat_table[node_index].name, st->name);
		stat_table[node_index].objs = st->objs;
		node_index++;
	}   
	return 0;
}


static int handle_telemetry_cmd_dpservices_node_stats(const char *cmd __rte_unused,
		const char *params, struct rte_tel_data *data)
{
	struct rte_tel_data *data1;
	int rc = 0, k = 0, l = 255, x = 0;
	int num_dict = nb_nodes/256;
	num_dict = nb_nodes % 256 == 0 ? num_dict : num_dict + 1;
	char dict_name[num_dict][RTE_NODE_NAMESIZE];

	stat_table = (struct graph_node_stat*)malloc(sizeof(struct graph_node_stat)*nb_nodes);
	if (!stat_table) {
		DPS_LOG_ERR("Cannot allocate stat table table");
		return rc;
	}

	if (telemetry_stats) 
		rte_graph_cluster_stats_get(telemetry_stats, 0); 

	rte_tel_data_start_dict(data);
	for(int z = 0; z < num_dict; ++z) {
		snprintf(dict_name[z], RTE_NODE_NAMESIZE, "Node_%d_to_%d", k, l);
		k = k + 256;
		l = l + 256;
		data1 = rte_tel_data_alloc();
		rte_tel_data_start_dict(data1);
		for (int m = 0; ( m < 8 && x < nb_nodes ); ++m, ++x) {
			rte_tel_data_add_dict_u64(data1, stat_table[x].name, stat_table[x].objs);
		}
	rte_tel_data_add_dict_container(data, dict_name[z], data1, 0);
	}
	node_index = 0;
	return rc; 
}

int dp_telemetry_init(void)
{
	if (DP_FAILED(rte_telemetry_register_cmd("/dp_service/graph/obj_count",
		handle_telemetry_cmd_dpservices_node_stats,
		"Returns objs count stat for a graph node."))) {
			DPS_LOG_ERR("Failed to register telemetry command");
			return DP_ERROR;
		}

	return DP_OK;
}

