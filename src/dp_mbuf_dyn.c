#include "dp_mbuf_dyn.h"
#include <rte_malloc.h>
#include "node_api.h"

__rte_always_inline struct dp_flow * get_dp_flow_ptr(struct rte_mbuf *m)
{
	if (!m)
		return NULL;
	return (struct dp_flow *)(m + 1);
}

__rte_always_inline struct dp_flow * alloc_dp_flow_ptr(struct rte_mbuf *m)
{
	if (!m)
		return NULL;

	return (struct dp_flow *)(m + 1);
}

__rte_always_inline void init_dp_mbuf_priv1(struct rte_mbuf *m)
{
	if (m)
		memset((void*)(m + 1), 0, sizeof(struct dp_flow));
}
