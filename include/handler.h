#ifndef _HANDLER_H_
#define _HANDLER_H_
#include <rte_mbuf.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Handler Types */
typedef enum {
	DP_UNDEFINED,
	DP_ARP_HANDLER,
	DP_NP_HANDLER,
    DP_DHCP_HANDLER,
    DP_FW_HANDLER,
    DP_NAT_HANDLER,
    DP_RTEFLOW_HANDLER,
	_DP_MAX_HANDLER,
} handler_type;

#define DP_MAX_HANDLER _DP_MAX_HANDLER - 1

struct hdlr_config {
	struct rte_mempool	*rte_mempool;
	int					port_id;
};

/* Handler context. Trailing part can be an union */
struct handler_ctx {
	struct hdlr_config	config;
	/* Handler specific union */
	union
	{
		struct { 
			void 	*my_arp_ptr;
		};
		/*
		* define new struct for each handler, if needed.
		*/
	};
};

/* Interface which every handler needs to implement */
struct handler_ops {
	handler_type 			type;
	struct handler_ctx*		(*init)();
	int						(*process_packet)(struct handler_ctx*, struct rte_mbuf *m);
	int						(*install_flow)(struct handler_ctx*);
	int						(*set_config)(struct handler_ctx*, struct hdlr_config*);
	int						(*exit)(struct handler_ctx*);
};

struct port_handler {
	struct handler_ops *ops;
	struct handler_ctx *ctx;
};

int dp_init_handler(handler_type h_type);
int dp_register_handler(struct handler_ops* ops);
struct port_handler* dp_create_handler(handler_type h_type);

#ifdef __cplusplus
}
#endif
#endif /* _HANDLER_H_ */

