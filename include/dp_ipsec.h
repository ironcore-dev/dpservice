// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#ifndef __INCLUDE_DP_IPSEC_H__
#define __INCLUDE_DP_IPSEC_H__

#include <stdint.h>
#include <stdbool.h>
#include <rte_byteorder.h>
#include <rte_crypto.h>
#include <rte_ether.h>
#include <rte_ip6.h>
#include <rte_ipsec.h>
#include <rte_ipsec_sad.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include "dp_ipaddr.h"

#ifdef __cplusplus
extern "C" {
#endif

// Security Associations are provisioned over gRPC and looked up per packet, see
// docs/concepts/ipsec.md for the deliberate limits of this proof-of-concept.
#define DP_IPSEC_MAX_KEY_LEN	16	// AES-128
#define DP_IPSEC_MAX_SALT_LEN	4	// implicit part of the GCM nonce, never on the wire
#define DP_IPSEC_IV_LEN		8	// explicit part of the GCM nonce, carried in the packet
#define DP_IPSEC_ICV_LEN	16
#define DP_IPSEC_AAD_LEN	8	// the ESP header, i.e. SPI and sequence number

// Security Associations are looked up on the first 64 bits of the underlay addresses only,
// so that one SA covers a peer host rather than each of its individual underlay addresses
// (dp_generate_ul_ipv6() only ever varies the lower half). The SAD itself matches all 16
// bytes exactly, it has no prefix support, so this is applied to every key that is built -
// on insert and on lookup alike, see dp_ipsec_build_key().
#define DP_IPSEC_ADDR_PREFIX_LEN	64

// Enough for a proof-of-concept's peers times VNIs, and small enough that the session pool
// costs nothing to pre-allocate
#define DP_IPSEC_MAX_SA		64

// Largest anti-replay window a Security Association may ask for, in packets. librte_ipsec only
// refuses above two million, where one association's bitmap alone costs a quarter of a megabyte,
// so the bound is drawn here instead: RFC 4303 recommends 64 as a minimum and 1024 for
// high-speed links, which this is comfortably above.
#define DP_IPSEC_REPLAY_WINDOW_MAX	4096

// librte_ipsec writes the whole AES-GCM nonce block - the salt, the explicit part carried in the
// packet, and the initial counter - into the private area of an allocated crypto operation, at
// the offset it takes from the transform the session was created with. The additional
// authenticated data does not live here: librte_ipsec puts it in the mbuf's tailroom, past the
// ICV, which is why a packet needs that many bytes of tailroom more than it ends up using.
#define DP_IPSEC_NONCE_BLOCK_LEN	16
#define DP_IPSEC_IV_OFFSET	(sizeof(struct rte_crypto_op) + sizeof(struct rte_crypto_sym_op))
#define DP_IPSEC_OP_PRIV_SIZE	DP_IPSEC_NONCE_BLOCK_LEN

// A Security Association is unidirectional (RFC 4301), so an entry only ever needs the one
// transform its direction implies
enum dp_ipsec_dir {
	DP_IPSEC_DIR_INGRESS,
	DP_IPSEC_DIR_EGRESS,
};

// Only one algorithm is supported, the enum exists so that a second one has an obvious place
// to land, in here and in the table in dp_ipsec.c that derives the key lengths from it
enum dp_ipsec_algo {
	DP_IPSEC_ALGO_AES_128_GCM,
	DP_IPSEC_ALGO_MAX,
};

// What the SAD stores. The addresses are already masked to DP_IPSEC_ADDR_PREFIX_LEN, and are
// kept so that a lookup result can be reported back and its entry removed without rebuilding
// the key from a packet.
struct dp_ipsec_sa {
	uint32_t			spi;
	enum dp_ipsec_algo	algo;
	enum dp_ipsec_dir	dir;
	union dp_ipv6		src;  // as seen on the wire in this SA's direction
	union dp_ipv6		dst;
	uint8_t				key[DP_IPSEC_MAX_KEY_LEN];
	uint8_t				salt[DP_IPSEC_MAX_SALT_LEN];
	uint16_t			salt_len;	// resolved from the algorithm, so the datapath needs no table
	// How far a packet may be reordered on the underlay before it is taken for a replay, in
	// packets. Zero disables replay checking altogether, which is what an association created
	// without the field asks for, and is the only value an egress association may carry.
	uint32_t			replay_window;
	void				*session;
	// librte_ipsec's view of this very association: it owns the ESP framing, the sequence
	// number and the anti-replay window, and drives the session above to do the crypto.
	// Separately allocated because its size depends on the replay window (rte_ipsec_sa_size()).
	// The sequence number lives in there and is not atomic, which is fine only because the graph
	// is limited to a single worker (see dp_graph_init()); revisit if that ever changes.
	struct rte_ipsec_sa			*ipsec_sa;
	struct rte_ipsec_session	ipsec_session;
};

// Everything needed to identify one SA, i.e. what the SAD is keyed on
struct dp_ipsec_sa_spec {
	uint32_t			spi;
	union dp_ipv6		src;
	union dp_ipv6		dst;
};

int dp_ipsec_init(int socket_id);
void dp_ipsec_free(void);

// Only valid after a successful dp_ipsec_init() in IPsec mode
struct rte_mempool *dp_ipsec_get_op_pool(void);

// Key material length is a property of the algorithm, so that a second cipher only has to be
// added to one table. Returns DP_ERROR for an unknown algorithm.
int dp_ipsec_get_key_len(enum dp_ipsec_algo algo);
int dp_ipsec_get_salt_len(enum dp_ipsec_algo algo);

// Security Association lifecycle. All three run on the worker thread, reached through the
// ordinary gRPC request path, and all return DP_GRPC_* codes.
// The SAD is written and read from that one thread only, which is why it carries no
// concurrency flags and why dp_ipsec_delete_sa() can free right away, see dp_ipsec.c.
int dp_ipsec_create_sa(const struct dp_ipsec_sa *request);
int dp_ipsec_delete_sa(const struct dp_ipsec_sa_spec *spec);
int dp_ipsec_get_sa(const struct dp_ipsec_sa_spec *spec, struct dp_ipsec_sa *out);

// Build a SAD key from an SPI and the two underlay addresses, masking them to the supported
// prefix length. This is the only place that decides what "the first 64 bits" means, and it is
// shared by both graph nodes and the gRPC handlers so they cannot drift apart.
void dp_ipsec_build_key(union rte_ipsec_sad_key *key /* out */,
						uint32_t spi, const union dp_ipv6 *src, const union dp_ipv6 *dst);

// Look up a whole burst at once. This is what rte_ipsec_sad_lookup() is built for, it
// prefetches and pipelines across the batch and chunks internally, so any count is fine.
// Entries that did not match are set to NULL.
void dp_ipsec_lookup_sa(const union rte_ipsec_sad_key *keys[], struct dp_ipsec_sa *sas[] /* out */,
						uint16_t count);

// Submit a whole burst and wait for it to complete. The chosen software PMD does the work
// inside the enqueue call, so this returns without ever really spinning.
// NOTE: completed operations are written back in completion order, which is not necessarily
// the order they were submitted in, so the caller has to find its packet via op->sym->m_src
// rather than by position.
uint16_t dp_ipsec_process_burst(struct rte_crypto_op *ops[], uint16_t count);

#ifdef __cplusplus
}
#endif

#endif
