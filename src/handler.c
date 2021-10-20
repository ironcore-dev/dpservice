#include "handlers/arp_handler.h"
#include "handler.h"

static struct handler_ops* handler_ops[DP_MAX_HANDLER];
static int handler_count = 0;

int dp_init_handler(handler_type h_type)
{
	switch (h_type)
	{
	case DP_ARP_HANDLER:
		register_arp_handler();
		break;
	/*TODO new handlers here */
	default:
		break;
	}
	return 0;
} 

int dp_register_handler(struct handler_ops* ops)
{
	handler_ops[handler_count++] = ops;
	return 0;
}

struct port_handler* dp_create_handler(handler_type h_type)
{
	struct port_handler *p_handler;
	int i;

	for (i = 0; i < DP_MAX_HANDLER; i++)
	{
		if (handler_ops[i]->type == h_type) {
			p_handler = malloc(sizeof(struct port_handler));
			p_handler->ctx = handler_ops[i]->init();
			p_handler->ops = handler_ops[i];
			return p_handler;
		} 
	}
	return NULL;
} 
