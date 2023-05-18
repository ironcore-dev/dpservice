#include "dp_mbuf_dyn.h"
#include <rte_malloc.h>

// TODO either move into headers or switch to -flto
// TODO return value never checked, add assertion here

__rte_always_inline struct dp_flow *get_dp_flow_ptr(struct rte_mbuf *m)
{
	if (!m)
		return NULL;

	return (struct dp_flow *)(m + 1);
}

__rte_always_inline struct dp_flow *init_dp_flow_ptr(struct rte_mbuf *m)
{
	if (!m)
		return NULL;

	memset(m + 1, 0, sizeof(struct dp_flow));
	return (struct dp_flow *)(m + 1);
}
