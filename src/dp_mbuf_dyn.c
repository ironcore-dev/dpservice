#include "rte_mbuf_dyn.h"
#include "dp_mbuf_dyn.h"

static const struct rte_mbuf_dynfield dp_mbuf_dynfield_desc = {
	.name = "dp_node_dynfield_flow_ptr",
	.size = sizeof(struct dp_mbuf_priv1),
	.align = __alignof__(struct dp_mbuf_priv1),
};

static int priv1_offset = -1;

struct dp_mbuf_priv1* get_dp_mbuf_priv1(struct rte_mbuf *m)
{
	if (priv1_offset >= 0) 
		return RTE_MBUF_DYNFIELD(m, priv1_offset, struct dp_mbuf_priv1 *);
	else
		return NULL;
}

void init_dp_mbuf_priv1(struct rte_mbuf *m)
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

