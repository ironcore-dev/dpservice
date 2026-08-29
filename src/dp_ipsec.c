// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include "dp_ipsec.h"
#include <rte_cryptodev.h>
#include <rte_dev.h>
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

#define DP_IPSEC_QUEUE_PAIR			0
#define DP_IPSEC_NB_QUEUE_PAIRS		1	// only one graph worker exists
#define DP_IPSEC_QP_DESCRIPTORS		2048
#define DP_IPSEC_NB_SESSIONS		2	// one for each direction
#define DP_IPSEC_OP_POOL_SIZE		1024
#define DP_IPSEC_OP_CACHE_SIZE		64
// The software PMD completes inside the enqueue call, this is only here so that a device
// that never completes an operation cannot hang the graph worker forever
#define DP_IPSEC_DEQUEUE_RETRIES	32

static const uint8_t dp_ipsec_key[DP_IPSEC_KEY_LEN] = {
	0x24, 0x7b, 0x0e, 0xa2, 0x51, 0xc9, 0x3d, 0x6f,
	0xb8, 0x40, 0x17, 0xe5, 0x9a, 0x2c, 0xd3, 0x86,
};

static const uint8_t dp_ipsec_salt[DP_IPSEC_SALT_LEN] = { 0x1b, 0xf4, 0x60, 0xa7 };

static uint8_t dp_ipsec_dev_id;
static struct rte_mempool *dp_ipsec_session_pool;
static struct rte_mempool *dp_ipsec_op_pool;
static void *dp_ipsec_encrypt_session;
static void *dp_ipsec_decrypt_session;
static uint64_t dp_ipsec_seq;
static bool dp_ipsec_active;

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

static void *dp_ipsec_create_session(enum rte_crypto_aead_operation operation)
{
	struct rte_crypto_sym_xform xform = {
		.type = RTE_CRYPTO_SYM_XFORM_AEAD,
		.aead = {
			.op = operation,
			.algo = RTE_CRYPTO_AEAD_AES_GCM,
			.key = {
				.data = dp_ipsec_key,
				.length = DP_IPSEC_KEY_LEN,
			},
			.iv = {
				.offset = DP_IPSEC_IV_OFFSET,
				.length = DP_IPSEC_SALT_LEN + DP_IPSEC_IV_LEN,
			},
			.digest_length = DP_IPSEC_ICV_LEN,
			.aad_length = DP_IPSEC_AAD_LEN,
		},
	};
	void *session;

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

int dp_ipsec_init(int socket_id)
{
	int ret;

	if (!dp_conf_is_ipsec_enabled())
		return DP_OK;

	if (DP_FAILED(dp_ipsec_create_device(socket_id))
		|| DP_FAILED(dp_ipsec_create_pools(socket_id)))
		return DP_ERROR;

	// AES-GCM encryption and decryption are separate transforms, so the one Security
	// Association needs one session for each direction
	dp_ipsec_encrypt_session = dp_ipsec_create_session(RTE_CRYPTO_AEAD_OP_ENCRYPT);
	dp_ipsec_decrypt_session = dp_ipsec_create_session(RTE_CRYPTO_AEAD_OP_DECRYPT);
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

	if (dp_ipsec_encrypt_session)
		rte_cryptodev_sym_session_free(dp_ipsec_dev_id, dp_ipsec_encrypt_session);
	if (dp_ipsec_decrypt_session)
		rte_cryptodev_sym_session_free(dp_ipsec_dev_id, dp_ipsec_decrypt_session);

	if (dp_ipsec_op_pool)
		rte_mempool_free(dp_ipsec_op_pool);
	if (dp_ipsec_session_pool)
		rte_mempool_free(dp_ipsec_session_pool);
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
