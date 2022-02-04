#include "dp_grpc_impl.h"
#include "dpdk_layer.h"


int dp_send_to_worker(dp_request *req)
{
	struct rte_mbuf *m = rte_pktmbuf_alloc(get_dpdk_layer()->rte_mempool);
	dp_request *head = rte_pktmbuf_mtod(m, dp_request*);

	*head = *req;

	if (rte_ring_sp_enqueue(get_dpdk_layer()->grpc_tx_queue, m))
		return EXIT_FAILURE;

	return EXIT_SUCCESS;
}

int dp_recv_from_worker(dp_reply *rep)
{
	struct rte_mbuf *m;
	dp_reply *head;

	if (!rte_ring_sc_dequeue(get_dpdk_layer()->grpc_rx_queue, (void**)&m)) {
		head = rte_pktmbuf_mtod(m, dp_reply*);
		*rep = *head;
		rte_pktmbuf_free(m);
		return EXIT_SUCCESS;
	}
	return EXIT_FAILURE;
}

__rte_always_inline void dp_fill_head(dp_com_head* head, uint16_t type,
									  uint8_t is_chained, uint8_t count)
{
	head->com_type = type;
	head->buf_count = count;
	head->is_chained = is_chained;
}

static int dp_process_hello(dp_request *req, dp_reply *rep)
{
	printf("On worker thread side received %x \n", req->hello);
	rep->hello = 0xbeeffeed;
	return EXIT_SUCCESS;
}

static int dp_process_addvip(dp_request *req, dp_reply *rep)
{
	int port_id;

	port_id = dp_get_portid_with_vm_handle(req->add_vip.machine_id);

	/* This machine ID doesnt exist */
	if (port_id < 0)
		return EXIT_FAILURE;

	if (req->add_vip.ip_type == RTE_ETHER_TYPE_IPV4) {
		dp_set_vm_nat_ip(port_id, ntohl(req->add_vip.vip.vip_addr));
	}
	return EXIT_SUCCESS;
}

static int dp_process_getvip(dp_request *req, dp_reply *rep)
{
	return EXIT_SUCCESS;
}

int dp_process_request(struct rte_mbuf *m)
{
	dp_request* req;
	dp_reply rep, *p_rep;
	int ret = EXIT_SUCCESS;

	req = rte_pktmbuf_mtod(m, dp_request*);

	switch (req->com_head.com_type)
	{
		case DP_REQ_TYPE_HELLO:
			ret = dp_process_hello(req, &rep);
			break;
		case DP_REQ_TYPE_ADDVIP:
			ret = dp_process_addvip(req, &rep);
			break;
		case DP_REQ_TYPE_GETVIP:
			ret = dp_process_getvip(req, &rep);
			break;
		default:
			break;
	}
	rep.com_head = req->com_head;
	
	p_rep = rte_pktmbuf_mtod(m, dp_reply*);
	*p_rep = rep;
	rte_ring_sp_enqueue(get_dpdk_layer()->grpc_rx_queue, m);

	return ret;
}