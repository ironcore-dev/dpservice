#include "handlers/arp_handler.h"
#include "handler.h"

#include <rte_ether.h>
#include <rte_ethdev.h>


static struct handler_ctx* arp_init()
{
	struct handler_ctx* hdlr_ctx;

	hdlr_ctx = malloc(sizeof(struct handler_ctx));

	return hdlr_ctx;
} 

static int arp_process_packet(struct handler_ctx* ctx, struct rte_mbuf *m)
{
	struct rte_ether_hdr *req_eth_hdr; 
	struct rte_arp_hdr *req_arp_hdr;

	req_eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	req_arp_hdr = (struct rte_arp_hdr*) (req_eth_hdr + 1);

	// Validate ethernet / IPv4 ARP values are correct
	if (req_arp_hdr->arp_hardware != ntohs(1))
		return 0;
	if (req_arp_hdr->arp_protocol != ntohs(0x0800))
		return 0;
	if (req_arp_hdr->arp_hlen != 6)
		return 0;
	if (req_arp_hdr->arp_plen != 4)
		return 0;

	if (req_arp_hdr->arp_opcode == ntohs(1)) {
		uint32_t  requested_ip = ntohl(req_arp_hdr->arp_data.arp_tip);
		printf("ARP request for IP %x\n ", requested_ip);

		//Respond to IP 192.168.123.3
		if (requested_ip == 0xc0a87b03) {
			struct rte_mbuf *mres = rte_pktmbuf_alloc(ctx->config.rte_mempool);
			struct rte_ether_hdr *resp_eth_hdr = rte_pktmbuf_mtod(mres, struct rte_ether_hdr *);
			struct rte_arp_hdr *resp_arp_hdr = (struct rte_arp_hdr*) (resp_eth_hdr + 1);
			resp_eth_hdr->ether_type = htons(0x0806);
			rte_ether_addr_copy(&req_arp_hdr->arp_data.arp_sha, &resp_eth_hdr->d_addr);

			uint8_t my_mac[] = {0x00, 0x00, 0xde, 0xad, 0xbe, 0xef};
			rte_memcpy(resp_eth_hdr->s_addr.addr_bytes, my_mac, 6);

			resp_arp_hdr->arp_hardware = htons(1);
			resp_arp_hdr->arp_protocol = htons(0x0800);
			resp_arp_hdr->arp_hlen = 6;
			resp_arp_hdr->arp_plen = 4;
			resp_arp_hdr->arp_opcode = htons(2);
			rte_memcpy(resp_arp_hdr->arp_data.arp_sha.addr_bytes, my_mac, 6);
			resp_arp_hdr->arp_data.arp_sip = req_arp_hdr->arp_data.arp_tip;
			resp_arp_hdr->arp_data.arp_tip = req_arp_hdr->arp_data.arp_sip;
			rte_ether_addr_copy(&req_arp_hdr->arp_data.arp_sha, &resp_arp_hdr->arp_data.arp_tha);

			mres->data_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);
			mres->pkt_len = mres->data_len;
			int sent = 0;
			sent = rte_eth_tx_burst(ctx->config.port_id, 0, &mres, 1);
			rte_pktmbuf_free(mres);
			printf("Sent out %d bytes\n", sent);
		}
	} 
	return 0;
} 

static int arp_set_config(struct handler_ctx* ctx, struct hdlr_config* config)
{
	ctx->config = *config;

	return 0;
} 

static int arp_install_flow(struct handler_ctx* ctx)
{
	return 0;
} 

static int arp_exit(struct handler_ctx* ctx)
{
	return 0;
} 

static struct handler_ops arp_ops = {
	.type   		= DP_ARP_HANDLER,
	.init			= arp_init,
	.set_config     = arp_set_config,
	.install_flow   = arp_install_flow,
	.process_packet	= arp_process_packet,
	.exit			= arp_exit,
};

int register_arp_handler() 
{
	dp_register_handler(&arp_ops);
	
	return 0;
} 