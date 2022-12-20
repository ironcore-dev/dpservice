#ifndef __INCLUDE_DP_PDUMP_CLIENT_H__
#define __INCLUDE_DP_PDUMP_CLIENT_H__

#include <net/if.h>

#include <rte_memzone.h>
#include <rte_mempool.h>
#include <rte_ring.h>

#ifdef __cplusplus
extern "C" {
#endif

// TODO yes, this is the same as server-size, merge maybe
struct dp_pdump_client {
	const struct rte_memzone *memzone;
	struct rte_mempool       *mempool;
	struct rte_ring          *ringbuf;
};

// TODO yes, yes, either merge or create a shared header
struct dp_pdump_iface {
	uint16_t port_id;
	uint8_t  port_name[IFNAMSIZ];
};
struct dp_pdump_shmem {
	uint16_t port_id;  // TODO comment, this having the same name as port above is confusing
	uint nb_ifaces;
	struct dp_pdump_iface ifaces[];
};

int dp_pdump_connect(struct dp_pdump_client *client);
int dp_pdump_connect_port(struct dp_pdump_client *client, uint16_t port_id);

#ifdef __cplusplus
}
#endif

#endif

