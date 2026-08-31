// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include "nodes/ipsec_encap_node.h"
#include <rte_common.h>
#include <rte_crypto.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_ipsec.h>
#include <rte_ipsec_group.h>
#include <rte_mbuf.h>
#include "dp_error.h"
#include "dp_ipsec.h"
#include "dp_log.h"
#include "dp_mbuf_dyn.h"
#include "dp_port.h"
#include "nodes/common_node.h"

DP_NODE_REGISTER_NOINIT(IPSEC_ENCAP, ipsec_encap, DP_NODE_DEFAULT_NEXT_ONLY);

static uint16_t next_tx_index[DP_MAX_PORTS];

int ipsec_encap_node_append_pf_tx(uint16_t port_id, const char *tx_node_name)
{
	return dp_node_append_pf_tx(DP_NODE_GET_SELF(ipsec_encap), next_tx_index, port_id, tx_node_name);
}

// There is no security policy database, so the outbound Security Association is selected by
// the underlay addresses ipip_encap has already written plus the VNI this packet belongs to,
// which is what its SPI is expected to be. The route's target VNI is deliberately not used:
// it is zero for every route created without one, which would key every association alike.
static __rte_always_inline void ipsec_encap_build_key(union rte_ipsec_sad_key *key, struct rte_mbuf *m)
{
	const struct rte_ether_hdr *ether_hdr = rte_pktmbuf_mtod(m, const struct rte_ether_hdr *);
	const struct rte_ipv6_hdr *ipv6_hdr = (const struct rte_ipv6_hdr *)(ether_hdr + 1);

	dp_ipsec_build_key(key, dp_get_in_port(m)->iface.vni,
					   dp_get_src_ipv6(ipv6_hdr), dp_get_dst_ipv6(ipv6_hdr));
}

// Hand the packet to librte_ipsec, which inserts the ESP header in-between the outer IPv6 header
// and what it tunnels, appends the padding and the trailer, and builds the operation that
// encrypts the result. The association is in transport mode, so it needs to be told where that
// outer header ends - ipip_encap deliberately leaves l2_len describing the packet inside it.
static __rte_always_inline int ipsec_encap_prepare(struct rte_mbuf *m,
												   struct rte_crypto_op **op,
												   struct dp_ipsec_sa *sa)
{
	m->l2_len = sizeof(struct rte_ether_hdr);
	m->l3_len = sizeof(struct rte_ipv6_hdr);

	if (unlikely(rte_ipsec_pkt_crypto_prepare(&sa->ipsec_session, &m, op, 1) != 1))
		return DP_ERROR;

	return DP_OK;
}

static __rte_always_inline rte_edge_t get_next_index(__rte_unused struct rte_node *node, struct rte_mbuf *m)
{
	struct dp_flow *df = dp_get_flow_ptr(m);

	if (unlikely(dp_get_pkt_mark(m)->flags.crypto_failed))
		return IPSEC_ENCAP_NEXT_DROP;

	return next_tx_index[df->nxt_hop];
}

// Unlike the other nodes, crypto is a burst operation, so the whole burst has to be
// submitted before any of its packets can be forwarded. Only the edge assignment is left
// to dp_foreach_graph_packet(), which is also what keeps graphtrace working here.
//
// A packet can be lost in three structurally different places, and each one says something
// different, so each gets its own line: before any crypto, in the crypto itself, and in what
// librte_ipsec does with the result afterwards. Production wants a counter for all three,
// one warning per bad packet is a flood risk.
static uint16_t ipsec_encap_node_process(struct rte_graph *graph,
										 struct rte_node *node,
										 void **objs,
										 uint16_t nb_objs)
{
	union rte_ipsec_sad_key keys[RTE_GRAPH_BURST_SIZE];
	const union rte_ipsec_sad_key *keyptrs[RTE_GRAPH_BURST_SIZE];
	struct dp_ipsec_sa *sas[RTE_GRAPH_BURST_SIZE];
	struct rte_crypto_op *ops[RTE_GRAPH_BURST_SIZE];
	struct rte_crypto_op *done[RTE_GRAPH_BURST_SIZE];
	const struct rte_crypto_op *readonly[RTE_GRAPH_BURST_SIZE];
	struct rte_mbuf *grouped[RTE_GRAPH_BURST_SIZE];
	struct rte_ipsec_group groups[RTE_GRAPH_BURST_SIZE];
	struct rte_mbuf *m;
	uint16_t nb_ops = 0;
	uint16_t nb_done;
	uint16_t nb_groups;

	// this is all-or-nothing, it does not allocate a smaller amount
	if (unlikely(rte_crypto_op_bulk_alloc(dp_ipsec_get_op_pool(), RTE_CRYPTO_OP_TYPE_SYMMETRIC,
										  ops, nb_objs) == 0)) {
		DPNODE_LOG_WARNING(node, "Cannot allocate crypto operations", DP_LOG_VALUE(nb_objs));
		for (uint16_t i = 0; i < nb_objs; ++i)
			dp_get_pkt_mark((struct rte_mbuf *)objs[i])->flags.crypto_failed = true;
		dp_foreach_graph_packet(graph, node, objs, nb_objs, DP_GRAPH_NO_SPECULATED_NODE, get_next_index);
		return nb_objs;
	}

	for (uint16_t i = 0; i < nb_objs; ++i) {
		m = (struct rte_mbuf *)objs[i];
		// fail closed: only a completed operation clears this again
		dp_get_pkt_mark(m)->flags.crypto_failed = true;
		keyptrs[i] = &keys[i];
		ipsec_encap_build_key(&keys[i], m);
	}

	dp_ipsec_lookup_sa(keyptrs, sas, nb_objs);

	for (uint16_t i = 0; i < nb_objs; ++i) {
		// No Security Association for this peer, so there is nothing to encrypt with and the
		// packet is dropped rather than leaving the fabric in the clear. Deliberately silent:
		// this is the expected state until the control plane has provisioned one, and a line
		// per packet would bury the failures that do matter. Production wants a counter here.
		if (!sas[i])
			continue;
		if (unlikely(DP_FAILED(ipsec_encap_prepare((struct rte_mbuf *)objs[i], &ops[nb_ops], sas[i])))) {
			// nothing has been encrypted yet, so this is a packet that cannot fit its ESP
			// overhead, or a sequence number space that has run out
			DPNODE_LOG_WARNING(node, "Cannot frame packet for encryption", DP_LOG_RET(-rte_errno));
			continue;
		}
		++nb_ops;
	}

	if (likely(nb_ops > 0)) {
		rte_memcpy(done, ops, nb_ops * sizeof(*done));
		nb_done = dp_ipsec_process_burst(done, nb_ops);

		// the grouping below only records *that* an operation failed, so the status is reported
		// from here, where it is still at hand
		for (uint16_t i = 0; i < nb_done; ++i) {
			if (unlikely(done[i]->status != RTE_CRYPTO_OP_STATUS_SUCCESS))
				DPNODE_LOG_WARNING(node, "Cannot encrypt packet", DP_LOG_VALUE(done[i]->status));
			// the grouping only reads the operations, but takes them as pointers to const,
			// which C does not convert to on its own
			readonly[i] = done[i];
		}

		// Operations come back in completion order, which is not the order they were submitted
		// in, and librte_ipsec finalizes one association at a time. Both are what this regroups.
		nb_groups = rte_ipsec_pkt_crypto_group(readonly, grouped, groups, nb_done);
		for (uint16_t i = 0; i < nb_groups; ++i) {
			struct rte_ipsec_group *grp = &groups[i];
			uint16_t nb_ok;

			// failures are moved to the end of the group, so everything before this succeeded
			nb_ok = rte_ipsec_pkt_process(grp->id.ptr, grp->m, (uint16_t)grp->cnt);
			for (uint16_t j = 0; j < (uint16_t)grp->cnt; ++j) {
				m = grp->m[j];
				if (j < nb_ok)
					dp_get_pkt_mark(m)->flags.crypto_failed = false;
				else if (!(m->ol_flags & RTE_MBUF_F_RX_SEC_OFFLOAD_FAILED))
					DPNODE_LOG_WARNING(node, "Cannot finalize encrypted packet");
				// receive-side flags the grouping raised, they have no business on a packet
				// that is about to be transmitted
				m->ol_flags &= ~(RTE_MBUF_F_RX_SEC_OFFLOAD | RTE_MBUF_F_RX_SEC_OFFLOAD_FAILED);
			}
		}
	}

	// freeing via the untouched array, the processed one is in completion order
	for (uint16_t i = 0; i < nb_objs; ++i)
		rte_crypto_op_free(ops[i]);

	dp_foreach_graph_packet(graph, node, objs, nb_objs, DP_GRAPH_NO_SPECULATED_NODE, get_next_index);
	return nb_objs;
}
