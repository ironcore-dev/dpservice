#include "rte_mbuf_dyn.h"
#include "dp_mbuf_dyn.h"
#include <rte_malloc.h>
#include "node_api.h"

static const struct rte_mbuf_dynfield dp_mbuf_dynfield_desc = {
	.name = "dp_node_dynfield_flow_ptr",
	.size = sizeof(struct dp_mbuf_priv1),
	.align = __alignof__(struct dp_mbuf_priv1),
};

static int priv1_offset = -1;

__rte_always_inline struct dp_mbuf_priv1* get_dp_mbuf_priv1(struct rte_mbuf *m)
{
	if (priv1_offset >= 0) 
		return RTE_MBUF_DYNFIELD(m, priv1_offset, struct dp_mbuf_priv1 *);
	else
		return NULL;
}

__rte_always_inline struct dp_flow * get_dp_flow_ptr(struct rte_mbuf *m)
{
	struct dp_mbuf_priv1 *dp_mbuf_p1 = NULL;

	dp_mbuf_p1 = get_dp_mbuf_priv1(m);
	if (!dp_mbuf_p1) {
		printf("Can not get private pointer\n");
		return NULL;
	}

	return dp_mbuf_p1->flow_ptr;
}

__rte_always_inline struct dp_flow * alloc_dp_flow_ptr(struct rte_mbuf *m)
{
	struct dp_mbuf_priv1 *dp_mbuf_p1 = NULL;

	dp_mbuf_p1 = get_dp_mbuf_priv1(m);
	if (!dp_mbuf_p1) {
		printf("Can not get private pointer\n");
		return NULL;
	}
	dp_mbuf_p1->flow_ptr = rte_zmalloc(__func__, sizeof(struct dp_flow),
										RTE_CACHE_LINE_SIZE);

	return dp_mbuf_p1->flow_ptr;
}


__rte_always_inline void init_dp_mbuf_priv1(struct rte_mbuf *m)
{
	if (priv1_offset >= 0) {
		struct dp_mbuf_priv1 *temp;
		temp = RTE_MBUF_DYNFIELD(m, priv1_offset, struct dp_mbuf_priv1 *);
		temp->flow_ptr = NULL;
	}	
}

int rte_mbuf_dyn_flow_register(int *field_offset)
{
	priv1_offset = rte_mbuf_dynfield_register(&dp_mbuf_dynfield_desc);
	if (priv1_offset < 0)
		return -1;

	return 0;
}

