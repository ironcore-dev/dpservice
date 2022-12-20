#include "monitoring/dp_pdump_client.h"
#include "monitoring/dp_pdump_priv.h"

// NOTE: no logging here, this is called from the client side

int dp_pdump_connect(struct dp_pdump_client *client)
{
	client->memzone = rte_memzone_lookup(DP_PDUMP_MEMZONE_NAME);
	if (!client->memzone)
		return -1;

	client->mempool = rte_mempool_lookup(DP_PDUMP_MEMPOOL_NAME);
	if (!client->mempool)
		return -1;

	client->ringbuf = rte_ring_lookup(DP_PDUMP_RINGBUF_NAME);
	if (!client->ringbuf)
		return -1;

	return 0;
}

int dp_pdump_connect_port(struct dp_pdump_client *client, uint16_t port_id)
{
	struct dp_pdump_shmem *shmem = (struct dp_pdump_shmem *)client->memzone->addr;

	// TODO validate port id

	// TODO use a proper atomic operation (although it's not that essential
	shmem->port_id = port_id;

	return 0;
}
