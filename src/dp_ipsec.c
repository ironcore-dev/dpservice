// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include "dp_ipsec.h"
#include <rte_cryptodev.h>
#include <rte_dev.h>
#include <rte_ipsec_sad.h>
#include <rte_malloc.h>
#include "dp_conf.h"
#include "dp_error.h"
#include "dp_log.h"

// Software crypto device driving the proof-of-concept. This is the only usable software
// PMD in the supported environments: the ipsec_mb family is x86-only and crypto_null is
// disabled in the DPDK build this project uses. Hardware devices (crypto_mlx5) will need
// this to become a configuration option.
#define DP_IPSEC_CRYPTODEV_NAME		"crypto_openssl0"

#define DP_IPSEC_SESSION_POOL_NAME	"ipsec_session_pool"
#define DP_IPSEC_OP_POOL_NAME		"ipsec_op_pool"
#define DP_IPSEC_SAD_NAME			"ipsec_sad"

#define DP_IPSEC_QUEUE_PAIR			0
#define DP_IPSEC_NB_QUEUE_PAIRS		1	// only one graph worker exists
#define DP_IPSEC_QP_DESCRIPTORS		2048
// One session per Security Association, plus the two of the hardcoded one
// TODO(ipsec-v2): drop the two together with the hardcoded Security Association
#define DP_IPSEC_NB_SESSIONS		(DP_IPSEC_MAX_SA + 2)
#define DP_IPSEC_OP_POOL_SIZE		1024
#define DP_IPSEC_OP_CACHE_SIZE		64
// The software PMD completes inside the enqueue call, this is only here so that a device
// that never completes an operation cannot hang the graph worker forever
#define DP_IPSEC_DEQUEUE_RETRIES	32

// TODO(ipsec-v2): the hardcoded Security Association, replaced by the SAD in a later commit
static const uint8_t dp_ipsec_key[DP_IPSEC_KEY_LEN] = {
	0x24, 0x7b, 0x0e, 0xa2, 0x51, 0xc9, 0x3d, 0x6f,
	0xb8, 0x40, 0x17, 0xe5, 0x9a, 0x2c, 0xd3, 0x86,
};

static const uint8_t dp_ipsec_salt[DP_IPSEC_SALT_LEN] = { 0x1b, 0xf4, 0x60, 0xa7 };

// Everything that varies between ciphers, so that adding one only means adding a row here
static const struct dp_ipsec_algo_spec {
	enum rte_crypto_aead_algorithm	aead_algo;
	uint16_t						key_len;
	uint16_t						salt_len;
	uint16_t						icv_len;
} dp_ipsec_algos[DP_IPSEC_ALGO_MAX] = {
	[DP_IPSEC_ALGO_AES_128_GCM] = {
		.aead_algo = RTE_CRYPTO_AEAD_AES_GCM,
		.key_len = 16,
		.salt_len = 4,
		.icv_len = DP_IPSEC_ICV_LEN,
	},
};

static uint8_t dp_ipsec_dev_id;
static struct rte_mempool *dp_ipsec_session_pool;
static struct rte_mempool *dp_ipsec_op_pool;
static void *dp_ipsec_encrypt_session;
static void *dp_ipsec_decrypt_session;
static uint64_t dp_ipsec_seq;
static bool dp_ipsec_active;

// The Security Association Database. Created without RTE_IPSEC_SAD_FLAG_RW_CONCURRENCY on
// purpose: gRPC requests are processed by rx_periodic (see dp_process_request()), which is a
// source node of the one graph dp_graph_init() allows, so the only writer to this table is
// the very thread that reads it. That flag would take an rte_rwlock on every datapath lookup
// to protect against a threading model this codebase refuses to start in. It is also why
// dp_ipsec_delete_sa() can free an entry right away instead of deferring it - no lookup
// result outlives the node call that obtained it. Both stop being true the day a second
// graph worker is allowed.
static struct rte_ipsec_sad *dp_ipsec_sad;
// Owning references to what the SAD points at, so that shutdown and the capacity check do not
// need an iterator the SAD does not offer. Holes are NULL.
static struct dp_ipsec_sa *dp_ipsec_sas[DP_IPSEC_MAX_SA];

struct rte_mempool *dp_ipsec_get_op_pool(void)
{
	return dp_ipsec_op_pool;
}

void *dp_ipsec_get_session(bool encrypt)
{
	return encrypt ? dp_ipsec_encrypt_session : dp_ipsec_decrypt_session;
}

const uint8_t *dp_ipsec_get_salt(void)
{
	return dp_ipsec_salt;
}

uint64_t dp_ipsec_next_seq(void)
{
	return ++dp_ipsec_seq;
}

int dp_ipsec_get_key_len(enum dp_ipsec_algo algo)
{
	if (unlikely(algo >= DP_IPSEC_ALGO_MAX))
		return DP_ERROR;

	return dp_ipsec_algos[algo].key_len;
}

int dp_ipsec_get_salt_len(enum dp_ipsec_algo algo)
{
	if (unlikely(algo >= DP_IPSEC_ALGO_MAX))
		return DP_ERROR;

	return dp_ipsec_algos[algo].salt_len;
}

static int dp_ipsec_create_device(int socket_id)
{
	struct rte_cryptodev_config config = {
		.socket_id = socket_id,
		.nb_queue_pairs = DP_IPSEC_NB_QUEUE_PAIRS,
	};
	struct rte_cryptodev_qp_conf qp_conf = {
		.nb_descriptors = DP_IPSEC_QP_DESCRIPTORS,
		.mp_session = NULL,  // sessions are created up-front, never sessionless
	};
	int ret;

	// rte_vdev_init() lives in the vdev bus driver, which a shared DPDK build does not
	// offer for linking; this is the public API that the driver itself ends up calling
	ret = rte_eal_hotplug_add("vdev", DP_IPSEC_CRYPTODEV_NAME, "");
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot create crypto device, is the PMD built?",
					DP_LOG_NAME(DP_IPSEC_CRYPTODEV_NAME), DP_LOG_RET(ret));
		return DP_ERROR;
	}

	ret = rte_cryptodev_get_dev_id(DP_IPSEC_CRYPTODEV_NAME);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Crypto device not found after creation",
					DP_LOG_NAME(DP_IPSEC_CRYPTODEV_NAME), DP_LOG_RET(ret));
		return DP_ERROR;
	}
	dp_ipsec_dev_id = (uint8_t)ret;

	ret = rte_cryptodev_configure(dp_ipsec_dev_id, &config);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot configure crypto device", DP_LOG_RET(ret));
		return DP_ERROR;
	}

	ret = rte_cryptodev_queue_pair_setup(dp_ipsec_dev_id, DP_IPSEC_QUEUE_PAIR, &qp_conf, socket_id);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot setup crypto queue pair", DP_LOG_RET(ret));
		return DP_ERROR;
	}

	return DP_OK;
}

// AES-GCM encryption and decryption are separate transforms, so a session belongs to exactly
// one direction, which is why a Security Association only ever needs one of them
static void *dp_ipsec_create_session(enum dp_ipsec_algo algo,
									 const uint8_t *key, const uint8_t *salt,
									 enum rte_crypto_aead_operation operation)
{
	const struct dp_ipsec_algo_spec *spec = &dp_ipsec_algos[algo];
	struct rte_crypto_sym_xform xform = {
		.type = RTE_CRYPTO_SYM_XFORM_AEAD,
		.aead = {
			.op = operation,
			.algo = spec->aead_algo,
			.key = {
				.data = key,
				.length = spec->key_len,
			},
			.iv = {
				.offset = DP_IPSEC_IV_OFFSET,
				.length = spec->salt_len + DP_IPSEC_IV_LEN,
			},
			.digest_length = spec->icv_len,
			.aad_length = DP_IPSEC_AAD_LEN,
		},
	};
	void *session;

	RTE_SET_USED(salt);  // the salt is not a part of the key, it is prepended to every nonce

	session = rte_cryptodev_sym_session_create(dp_ipsec_dev_id, &xform, dp_ipsec_session_pool);
	if (!session)
		DPS_LOG_ERR("Cannot create crypto session", DP_LOG_RET(rte_errno));

	return session;
}

static int dp_ipsec_create_pools(int socket_id)
{
	uint32_t session_size;

	session_size = rte_cryptodev_sym_get_private_session_size(dp_ipsec_dev_id);

	dp_ipsec_session_pool = rte_cryptodev_sym_session_pool_create(DP_IPSEC_SESSION_POOL_NAME,
																  DP_IPSEC_NB_SESSIONS, session_size,
																  0, 0, socket_id);
	if (!dp_ipsec_session_pool) {
		DPS_LOG_ERR("Cannot create crypto session pool", DP_LOG_RET(rte_errno));
		return DP_ERROR;
	}

	// The private data holds the nonce and the authenticated data, see dp_ipsec_prepare_op()
	dp_ipsec_op_pool = rte_crypto_op_pool_create(DP_IPSEC_OP_POOL_NAME, RTE_CRYPTO_OP_TYPE_SYMMETRIC,
												 DP_IPSEC_OP_POOL_SIZE, DP_IPSEC_OP_CACHE_SIZE,
												 DP_IPSEC_OP_PRIV_SIZE, socket_id);
	if (!dp_ipsec_op_pool) {
		DPS_LOG_ERR("Cannot create crypto operation pool", DP_LOG_RET(rte_errno));
		return DP_ERROR;
	}

	return DP_OK;
}

static int dp_ipsec_create_sad(int socket_id)
{
	struct rte_ipsec_sad_conf conf = {
		.socket_id = socket_id,
		.max_sa = {
			// Every specific rule also gets an entry in the SPI-only table, one per distinct
			// SPI, so that one has to be sized too or adds would fail past its default of 8
			[RTE_IPSEC_SAD_SPI_ONLY] = DP_IPSEC_MAX_SA,
			[RTE_IPSEC_SAD_SPI_DIP_SIP] = DP_IPSEC_MAX_SA,
		},
		.flags = RTE_IPSEC_SAD_FLAG_IPV6,
	};

	dp_ipsec_sad = rte_ipsec_sad_create(DP_IPSEC_SAD_NAME, &conf);
	if (!dp_ipsec_sad) {
		DPS_LOG_ERR("Cannot create the Security Association Database", DP_LOG_RET(rte_errno));
		return DP_ERROR;
	}

	return DP_OK;
}

int dp_ipsec_init(int socket_id)
{
	int ret;

	if (!dp_conf_is_ipsec_enabled())
		return DP_OK;

	if (DP_FAILED(dp_ipsec_create_device(socket_id))
		|| DP_FAILED(dp_ipsec_create_pools(socket_id))
		|| DP_FAILED(dp_ipsec_create_sad(socket_id)))
		return DP_ERROR;

	// TODO(ipsec-v2): goes away once both nodes resolve their Security Association per packet
	dp_ipsec_encrypt_session = dp_ipsec_create_session(DP_IPSEC_ALGO_AES_128_GCM,
													   dp_ipsec_key, dp_ipsec_salt,
													   RTE_CRYPTO_AEAD_OP_ENCRYPT);
	dp_ipsec_decrypt_session = dp_ipsec_create_session(DP_IPSEC_ALGO_AES_128_GCM,
													   dp_ipsec_key, dp_ipsec_salt,
													   RTE_CRYPTO_AEAD_OP_DECRYPT);
	if (!dp_ipsec_encrypt_session || !dp_ipsec_decrypt_session)
		return DP_ERROR;

	ret = rte_cryptodev_start(dp_ipsec_dev_id);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot start crypto device", DP_LOG_RET(ret));
		return DP_ERROR;
	}

	dp_ipsec_active = true;
	DPS_LOG_INFO("IPsec enabled", DP_LOG_NAME(DP_IPSEC_CRYPTODEV_NAME));
	return DP_OK;
}

void dp_ipsec_free(void)
{
	if (dp_ipsec_active) {
		rte_cryptodev_stop(dp_ipsec_dev_id);
		dp_ipsec_active = false;
	}

	for (size_t i = 0; i < RTE_DIM(dp_ipsec_sas); ++i) {
		if (!dp_ipsec_sas[i])
			continue;
		rte_cryptodev_sym_session_free(dp_ipsec_dev_id, dp_ipsec_sas[i]->session);
		rte_free(dp_ipsec_sas[i]);
		dp_ipsec_sas[i] = NULL;
	}

	if (dp_ipsec_sad) {
		rte_ipsec_sad_destroy(dp_ipsec_sad);
		dp_ipsec_sad = NULL;
	}

	if (dp_ipsec_encrypt_session)
		rte_cryptodev_sym_session_free(dp_ipsec_dev_id, dp_ipsec_encrypt_session);
	if (dp_ipsec_decrypt_session)
		rte_cryptodev_sym_session_free(dp_ipsec_dev_id, dp_ipsec_decrypt_session);

	if (dp_ipsec_op_pool)
		rte_mempool_free(dp_ipsec_op_pool);
	if (dp_ipsec_session_pool)
		rte_mempool_free(dp_ipsec_session_pool);
}

void dp_ipsec_build_key(union rte_ipsec_sad_key *key,
						uint32_t spi, const union dp_ipv6 *src, const union dp_ipv6 *dst)
{
	// The SAD matches all sixteen bytes, so the prefix length lives in the keys handed to it
	union dp_ipv6 masked_src = { ._prefix = src->_prefix, ._suffix = 0 };
	union dp_ipv6 masked_dst = { ._prefix = dst->_prefix, ._suffix = 0 };

	static_assert(DP_IPSEC_ADDR_PREFIX_LEN == 64, "dp_ipsec_build_key() only masks at 64 bits");

	key->v6.spi = spi;
	dp_ipv6_to_rte(&masked_dst, &key->v6.dip);
	dp_ipv6_to_rte(&masked_src, &key->v6.sip);
}

void dp_ipsec_lookup_sa(const union rte_ipsec_sad_key *keys[], struct dp_ipsec_sa *sas[], uint16_t count)
{
	// Entries that do not match are set to NULL by the lookup itself
	rte_ipsec_sad_lookup(dp_ipsec_sad, keys, (void **)sas, count);
}

static struct dp_ipsec_sa *dp_ipsec_lookup_one(const struct dp_ipsec_sa_spec *spec)
{
	union rte_ipsec_sad_key key;
	const union rte_ipsec_sad_key *keyptr = &key;
	struct dp_ipsec_sa *sa = NULL;

	dp_ipsec_build_key(&key, spec->spi, &spec->src, &spec->dst);
	dp_ipsec_lookup_sa(&keyptr, &sa, 1);

	return sa;
}

// Every underlay address this instance generates takes its first 64 bits from the configured
// underlay address (see dp_generate_ul_ipv6()), so a Security Association whose local side
// says anything else could never match a packet. Refusing it at creation turns a swapped pair
// of addresses into an error instead of a tunnel that silently drops everything.
static bool dp_ipsec_is_local_side_valid(const struct dp_ipsec_sa *request)
{
	const union dp_ipv6 *local = request->dir == DP_IPSEC_DIR_EGRESS ? &request->src : &request->dst;

	return local->_prefix == dp_conf_get_underlay_ip()->_prefix;
}

int dp_ipsec_create_sa(const struct dp_ipsec_sa *request)
{
	struct dp_ipsec_sa_spec spec = {
		.spi = request->spi,
		.src = request->src,
		.dst = request->dst,
	};
	union rte_ipsec_sad_key key;
	struct dp_ipsec_sa *sa;
	size_t slot;
	int ret;

	if (!dp_ipsec_sad)
		return DP_GRPC_ERR_SA_DISABLED;

	if (request->algo >= DP_IPSEC_ALGO_MAX)
		return DP_GRPC_ERR_SA_ALGO;

	if (!dp_ipsec_is_local_side_valid(request))
		return DP_GRPC_ERR_SA_BAD_ADDR;

	// The SAD would silently overwrite the entry and leak what it used to point at, because
	// rte_hash_add_key_with_hash_data() updates an existing key and reports success
	if (dp_ipsec_lookup_one(&spec))
		return DP_GRPC_ERR_SA_EXISTS;

	for (slot = 0; slot < RTE_DIM(dp_ipsec_sas); ++slot)
		if (!dp_ipsec_sas[slot])
			break;
	if (slot == RTE_DIM(dp_ipsec_sas))
		return DP_GRPC_ERR_LIMIT_REACHED;

	// rte_ipsec_sad_add() requires the stored pointer to be at least 4-byte aligned
	sa = rte_zmalloc("ipsec_sa", sizeof(*sa), RTE_CACHE_LINE_SIZE);
	if (!sa) {
		DPS_LOG_ERR("Cannot allocate Security Association");
		return DP_GRPC_ERR_OUT_OF_MEMORY;
	}

	// union dp_ipv6 has const members, so the struct cannot be assigned as a whole
	rte_memcpy(sa, request, sizeof(*sa));
	sa->seq = 0;
	sa->session = dp_ipsec_create_session(sa->algo, sa->key, sa->salt,
										  sa->dir == DP_IPSEC_DIR_EGRESS
											  ? RTE_CRYPTO_AEAD_OP_ENCRYPT
											  : RTE_CRYPTO_AEAD_OP_DECRYPT);
	if (!sa->session) {
		rte_free(sa);
		return DP_GRPC_ERR_SA_CREATE;
	}

	dp_ipsec_build_key(&key, sa->spi, &sa->src, &sa->dst);
	// Store what is actually matched, so that a later lookup or delete needs no re-masking
	dp_ipv6_from_rte(&sa->src, &key.v6.sip);
	dp_ipv6_from_rte(&sa->dst, &key.v6.dip);

	ret = rte_ipsec_sad_add(dp_ipsec_sad, &key, RTE_IPSEC_SAD_SPI_DIP_SIP, sa);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot add Security Association to the database", DP_LOG_RET(ret));
		rte_cryptodev_sym_session_free(dp_ipsec_dev_id, sa->session);
		rte_free(sa);
		return DP_GRPC_ERR_SA_CREATE;
	}

	dp_ipsec_sas[slot] = sa;
	return DP_GRPC_OK;
}

int dp_ipsec_delete_sa(const struct dp_ipsec_sa_spec *spec)
{
	union rte_ipsec_sad_key key;
	struct dp_ipsec_sa *sa;
	int ret;

	if (!dp_ipsec_sad)
		return DP_GRPC_ERR_SA_DISABLED;

	sa = dp_ipsec_lookup_one(spec);
	if (!sa)
		return DP_GRPC_ERR_SA_NOT_FOUND;

	dp_ipsec_build_key(&key, spec->spi, &spec->src, &spec->dst);
	ret = rte_ipsec_sad_del(dp_ipsec_sad, &key, RTE_IPSEC_SAD_SPI_DIP_SIP);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot remove Security Association from the database", DP_LOG_RET(ret));
		return DP_GRPC_ERR_SA_NOT_FOUND;
	}

	// Freeing right away is safe: the only thread that can be holding this pointer is the one
	// running here, and no lookup result outlives the node call that obtained it
	for (size_t i = 0; i < RTE_DIM(dp_ipsec_sas); ++i) {
		if (dp_ipsec_sas[i] != sa)
			continue;
		dp_ipsec_sas[i] = NULL;
		break;
	}
	rte_cryptodev_sym_session_free(dp_ipsec_dev_id, sa->session);
	rte_free(sa);

	return DP_GRPC_OK;
}

int dp_ipsec_get_sa(const struct dp_ipsec_sa_spec *spec, struct dp_ipsec_sa *out)
{
	struct dp_ipsec_sa *sa;

	if (!dp_ipsec_sad)
		return DP_GRPC_ERR_SA_DISABLED;

	sa = dp_ipsec_lookup_one(spec);
	if (!sa)
		return DP_GRPC_ERR_SA_NOT_FOUND;

	rte_memcpy(out, sa, sizeof(*out));
	return DP_GRPC_OK;
}

void dp_ipsec_prepare_op(struct rte_crypto_op *op, struct rte_mbuf *m,
						 const struct dp_esp_hdr *esp_hdr, uint32_t crypt_len, bool encrypt)
{
	uint8_t *nonce = rte_crypto_op_ctod_offset(op, uint8_t *, DP_IPSEC_IV_OFFSET);
	uint8_t *aad = rte_crypto_op_ctod_offset(op, uint8_t *, DP_IPSEC_AAD_OFFSET);

	// GCM's nonce is the secret salt followed by the explicit part carried in the packet
	rte_memcpy(nonce, dp_ipsec_salt, DP_IPSEC_SALT_LEN);
	rte_memcpy(nonce + DP_IPSEC_SALT_LEN, esp_hdr + 1, DP_IPSEC_IV_LEN);

	// only the ESP header is authenticated, everything in front of it is not
	rte_memcpy(aad, esp_hdr, DP_IPSEC_AAD_LEN);

	op->sym->m_src = m;
	op->sym->aead.data.offset = DP_IPSEC_OUTER_LEN + DP_IPSEC_HDR_LEN;
	op->sym->aead.data.length = crypt_len;
	op->sym->aead.aad.data = aad;
	op->sym->aead.aad.phys_addr = rte_crypto_op_ctophys_offset(op, DP_IPSEC_AAD_OFFSET);
	op->sym->aead.digest.data = rte_pktmbuf_mtod_offset(m, uint8_t *,
													   DP_IPSEC_OUTER_LEN + DP_IPSEC_HDR_LEN + crypt_len);
	op->sym->aead.digest.phys_addr = rte_pktmbuf_iova_offset(m,
															DP_IPSEC_OUTER_LEN + DP_IPSEC_HDR_LEN + crypt_len);

	rte_crypto_op_attach_sym_session(op, dp_ipsec_get_session(encrypt));
}

uint16_t dp_ipsec_process_burst(struct rte_crypto_op *ops[], uint16_t count)
{
	uint16_t enqueued;
	uint16_t dequeued = 0;

	enqueued = rte_cryptodev_enqueue_burst(dp_ipsec_dev_id, DP_IPSEC_QUEUE_PAIR, ops, count);
	if (unlikely(enqueued < count))
		DPS_LOG_WARNING("Cannot enqueue all crypto operations", DP_LOG_VALUE(enqueued), DP_LOG_MAX(count));

	for (int i = 0; i < DP_IPSEC_DEQUEUE_RETRIES && dequeued < enqueued; ++i)
		dequeued += rte_cryptodev_dequeue_burst(dp_ipsec_dev_id, DP_IPSEC_QUEUE_PAIR,
												&ops[dequeued], enqueued - dequeued);

	if (unlikely(dequeued < enqueued))
		DPS_LOG_WARNING("Crypto operations did not complete", DP_LOG_VALUE(dequeued), DP_LOG_MAX(enqueued));

	return dequeued;
}
