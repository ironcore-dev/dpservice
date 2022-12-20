#ifndef __INCLUDE_DP_PDUMP_H__
#define __INCLUDE_DP_PDUMP_H__

#include <net/if.h>

#include <rte_memzone.h>
#include <rte_mempool.h>
#include <rte_ring.h>
#include <rte_mbuf.h>

#ifdef __cplusplus
extern "C" {
#endif

struct dp_pdump {
	const struct rte_memzone *memzone;
	struct rte_mempool       *mempool;
	struct rte_ring          *ringbuf;
};

int dp_pdump_init(struct dp_pdump *pdump);
void dp_pdump_cleanup(struct dp_pdump *pdump);

struct dp_pdump_iface {
	uint16_t port_id;
	uint8_t  port_name[IFNAMSIZ];
};

struct dp_pdump_shmem {
	uint16_t port_id;  // TODO comment, this having the same name as port above is confusing
	uint nb_ifaces;
	struct dp_pdump_iface ifaces[];
};

// static __rte_always_inline
// bool dp_pdump_is_port_monitored(struct dp_pdump *pdump, uint16_t port_id)
// {
// 	struct dp_pdump_shmem *shmem = (struct dp_pdump_shmem *)pdump;
//
// 	return shmem->port_id == port_id;
// }


// TODO need a way to enable/disable, but that should maybe be done elsewhere
// (simply not calling pdump in rx/tx nodes then)

int dp_pdump_copy_burst(struct dp_pdump *pdump, uint16_t port_id,
						struct rte_mbuf **pkts, uint16_t nb_pkts);


static __rte_always_inline
void dp_pdump_dump_if_monitored(struct dp_pdump *pdump, uint16_t port_id,
								struct rte_mbuf **pkts, uint16_t nb_pkts)
{
	struct dp_pdump_shmem *shmem = (struct dp_pdump_shmem *)pdump->memzone->addr;

	if (likely(shmem->port_id != port_id))
		return;

	// TODO willfully ignore errors? mostly because of buffer full?
	dp_pdump_copy_burst(pdump, port_id, pkts, nb_pkts);
}

#ifdef __cplusplus
}
#endif

#endif

