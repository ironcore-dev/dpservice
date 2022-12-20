#include "monitoring/dp_pdump.h"

#include <rte_malloc.h>

#include "dp_port.h"
#include "dpdk_layer.h"
#include "dp_util.h"
#include "monitoring/dp_pdump_priv.h"


void dp_pdump_cleanup(struct dp_pdump *pdump)
{
	// TODO if memzone
	struct dp_pdump_shmem *shmem = (struct dp_pdump_shmem *)pdump->memzone->addr;

	rte_free(shmem->ifaces);

	rte_ring_free(pdump->ringbuf);
	rte_mempool_free(pdump->mempool);
	rte_memzone_free(pdump->memzone);
}


static inline int dp_pdump_shmem_init(struct dp_pdump_shmem *shmem)
{
	// TODO maybe do not copy it here, jsut allocate the layer ports directly as shared?
	struct dp_dpdk_layer *dpdk_layer = get_dpdk_layer();

	shmem->port_id = -1;  // disable dumping
	shmem->nb_ifaces = dpdk_layer->dp_port_cnt;

	for (uint i = 0; i < shmem->nb_ifaces; ++i) {
		struct dp_port *port = dpdk_layer->ports[i];
		shmem->ifaces[i].port_id = port->dp_port_id;
		// TODO why is cast needed??
		const char *name = port->dp_p_type == DP_PORT_PF ? port->dp_port_ext.port_name : (const char *)port->vf_name;
		rte_memcpy(shmem->ifaces[i].port_name, name, IFNAMSIZ);  // TODO min(sizeof(), sizeof())? but also ternary -^
	}

	return 0;
}

int dp_pdump_init(struct dp_pdump *pdump)
{
	// clear to make freeing on error safe
	memset(pdump, 0, sizeof(*pdump));

	// TODO checkpatch
	// TODO move into wrapper above
	uint port_cnt = get_dpdk_layer()->dp_port_cnt;
	// TODO pack(0) ??
	size_t reserve = sizeof(struct dp_pdump_shmem) + sizeof(struct dp_pdump_iface) * port_cnt;

	pdump->memzone = rte_memzone_reserve(DP_PDUMP_MEMZONE_NAME,
										 reserve,
										 SOCKET_ID_ANY,
										 0);
	if (!pdump->memzone) {
		DPS_LOG(CRIT, DPSERVICE, "Cannot create pdump shared memory\n");
		return -1;
	}

	if (dp_pdump_shmem_init((struct dp_pdump_shmem *)pdump->memzone->addr) < 0) {
		dp_pdump_cleanup(pdump);
		return -1;
	}

	// TODO (ask gg) not sure about this being pktmbuf and about the constants here
	pdump->mempool = rte_pktmbuf_pool_create(DP_PDUMP_MEMPOOL_NAME, NB_MBUF(DP_MAX_PORTS),
											 MEMPOOL_CACHE_SIZE, RTE_CACHE_LINE_SIZE + 32,
											 RTE_MBUF_DEFAULT_BUF_SIZE,
											 rte_socket_id());
	if (!pdump->mempool) {
		DPS_LOG(CRIT, DPSERVICE, "Cannot init pdump pool\n");
		dp_pdump_cleanup(pdump);
		return -1;
	}

	// TODO (ask gg) not sure about size constants
	// TODO dpdk uses multi producer multi consumer?
	pdump->ringbuf = rte_ring_create(DP_PDUMP_RINGBUF_NAME,
									 RTE_GRAPH_BURST_SIZE,
									 rte_socket_id(),
									 RING_F_SC_DEQ | RING_F_SP_ENQ);
	if (!pdump->ringbuf) {
		DPS_LOG(CRIT, DPSERVICE, "Cannot create pdump ring buffer\n");
		dp_pdump_cleanup(pdump);
		return -1;
	}

	return 0;
}


int dp_pdump_copy_burst(struct dp_pdump *pdump, uint16_t port_id, struct rte_mbuf **pkts, uint16_t nb_pkts)
{
	uint16_t nb_dups = 0;
	struct rte_mbuf *dups[nb_pkts];
	struct rte_mbuf *dup;
	uint sent;

	// TODO should we support pcapng format? (DPDK does)
	// (it also uses port number, queue number, directions, etc)
	// see rte_pdump.c::pdump_copy()

	// TODO BPF filtering here? (guess not)
	// TODO see rte_pdump.c::pdump_copy()

	// TODO add port id in headroom as a solution to multi-port monitoring?
	RTE_SET_USED(port_id);

	for (uint i = 0; i < nb_pkts; ++i) {
		dup = rte_pktmbuf_copy(pkts[i], pdump->mempool, 0, UINT32_MAX);
		if (unlikely(!dup))
			DPS_LOG(WARNING, DPSERVICE, "Cannot duplicate packet for pdump\n");
		else
			dups[nb_dups++] = dup;
	}

	// TODO acutally use the last argument to know when full/empty and do something about it?
	sent = rte_ring_enqueue_burst(pdump->ringbuf, (void *)dups, nb_dups, NULL);
	if (unlikely(sent < nb_dups)) {
		// TODO maybe no logging here, this is actually OK when nobody connected
		// (will we do enable/disable or not?)
		DPS_LOG(INFO, DPSERVICE, "Pdump ring is full\n");
		rte_pktmbuf_free_bulk(&dups[sent], nb_dups - sent);
	}

	return sent;
}
