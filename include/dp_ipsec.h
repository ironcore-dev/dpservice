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
#include <rte_mbuf.h>
#include <rte_mempool.h>

#ifdef __cplusplus
extern "C" {
#endif

// The proof-of-concept uses a single hardcoded Security Association, shared by both
// directions. There is no policy database and no key distribution yet, see
// docs/concepts/ipsec.md for the full list of deliberate limits.
#define DP_IPSEC_SPI		0xdb5ec001

#define DP_IPSEC_KEY_LEN	16	// AES-128
#define DP_IPSEC_SALT_LEN	4	// implicit part of the GCM nonce, never on the wire
#define DP_IPSEC_IV_LEN		8	// explicit part of the GCM nonce, carried in the packet
#define DP_IPSEC_ICV_LEN	16
#define DP_IPSEC_AAD_LEN	8	// the ESP header, i.e. SPI and sequence number
#define DP_IPSEC_BLOCK_SIZE	4	// ESP requires the ciphertext to be 4-byte aligned

// The nonce and a copy of the additional authenticated data are kept in the private area of
// an allocated crypto operation. The data is copied rather than pointed at inside the packet,
// because a PMD is allowed to write into the buffer it is given.
#define DP_IPSEC_NONCE_LEN	(DP_IPSEC_SALT_LEN + DP_IPSEC_IV_LEN)
#define DP_IPSEC_IV_OFFSET	(sizeof(struct rte_crypto_op) + sizeof(struct rte_crypto_sym_op))
#define DP_IPSEC_AAD_OFFSET	(DP_IPSEC_IV_OFFSET + DP_IPSEC_NONCE_LEN)
#define DP_IPSEC_OP_PRIV_SIZE	(DP_IPSEC_NONCE_LEN + DP_IPSEC_AAD_LEN)

// What ipip_encap has already put in front of the tunneled packet
#define DP_IPSEC_OUTER_LEN	((uint32_t)(sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv6_hdr)))

struct dp_esp_hdr {
	rte_be32_t spi;
	rte_be32_t seq;
};

// Trailing bytes of the encrypted part: padding, then this
struct dp_esp_tail {
	uint8_t pad_len;
	uint8_t next_proto;
};

// Bytes added in front of the tunneled packet (in-between the outer IPv6 header and it)
#define DP_IPSEC_HDR_LEN	((uint32_t)(sizeof(struct dp_esp_hdr) + DP_IPSEC_IV_LEN))
// Bytes added after the tunneled packet, excluding padding
#define DP_IPSEC_TAIL_LEN	((uint32_t)(sizeof(struct dp_esp_tail) + DP_IPSEC_ICV_LEN))

int dp_ipsec_init(int socket_id);
void dp_ipsec_free(void);

// Only valid after a successful dp_ipsec_init() in IPsec mode
struct rte_mempool *dp_ipsec_get_op_pool(void);
void *dp_ipsec_get_session(bool encrypt);
const uint8_t *dp_ipsec_get_salt(void);

// Sequence numbers start at 1 (RFC 4303) and double as the explicit nonce, which is what
// guarantees a GCM nonce is never reused under this key. Not atomic on purpose: the graph
// is limited to a single worker (see dp_graph_init()), and this needs revisiting if that
// ever changes.
uint64_t dp_ipsec_next_seq(void);

// Submit a whole burst and wait for it to complete. The chosen software PMD does the work
// inside the enqueue call, so this returns without ever really spinning.
// NOTE: completed operations are written back in completion order, which is not necessarily
// the order they were submitted in, so the caller has to find its packet via op->sym->m_src
// rather than by position.
uint16_t dp_ipsec_process_burst(struct rte_crypto_op *ops[], uint16_t count);

// Fill in everything a symmetric AEAD operation needs to encrypt or decrypt the part of the
// packet that follows the ESP header, whose nonce this also picks up.
void dp_ipsec_prepare_op(struct rte_crypto_op *op, struct rte_mbuf *m,
						 const struct dp_esp_hdr *esp_hdr, uint32_t crypt_len, bool encrypt);

#ifdef __cplusplus
}
#endif

#endif
