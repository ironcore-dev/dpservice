// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <arpa/inet.h>
#include "dp_error.h"
#include "rte_rib6.h"
#include "dp_maglev.h"

#include <stdint.h>

/* Implementation is based on maglev paper pseudo-code */
#define DP_MURMURHASH2_MAGIC	0x5bd1e995
#define DP_DJB_HASH_MAGIC		5381
#define DP_MAGLEV_POS_FREE		-1
#define DP_SHIFT_UP				true
#define DP_SHIFT_DOWN			false

static uint32_t dp_murmur_hash2(const union dp_ipv6 *ipv6)
{
	uint32_t len = sizeof(ipv6->bytes);
	const uint8_t *data = ipv6->bytes;
	uint32_t h = 0 ^ len;
	uint32_t k;

	while (len >= 4) {
		k = data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24);

		k *= DP_MURMURHASH2_MAGIC;
		k ^= k >> 24;
		k *= DP_MURMURHASH2_MAGIC;

		h *= DP_MURMURHASH2_MAGIC;
		h ^= k;

		data += 4;
		len -= 4;
	}

	switch (len) {
	case 3:
		h ^= data[2] << 16; // Fall through
	case 2:
		h ^= data[1] << 8;  // Fall through
	case 1:
		h ^= data[0];
		h *= DP_MURMURHASH2_MAGIC;
		break;
	default:
		break;
	}

	h ^= h >> 13;
	h *= DP_MURMURHASH2_MAGIC;
	h ^= h >> 15;

	return h;
}

static uint32_t dp_djb_hash(const union dp_ipv6 *ipv6)
{
	uint32_t hash = DP_DJB_HASH_MAGIC;
	const uint8_t *byte = ipv6->bytes;
	int c;

	// TODO FIX in separate commit
	while ((c = *byte++))
		hash = ((hash << 5) + hash) + c;

	hash &= ~(1 << 31);
	return hash;
}

static int *dp_maglev_permutation(struct lb_value *lbval)
{
	int  i, j, size, *permutation;
	uint32_t offset, skip;

	size = lbval->back_end_cnt * DP_LB_MAGLEV_LOOKUP_SIZE;
	permutation = rte_zmalloc("maglev_perm", sizeof(int) * size, RTE_CACHE_LINE_SIZE);
	if (!permutation) {
		DPS_LOG_ERR("Maglev permutation memory allocation failed");
		return NULL;
	}

	for (i = 0; i < lbval->back_end_cnt; i++) {
		offset = dp_murmur_hash2(&lbval->back_end_ips[i]) % DP_LB_MAGLEV_LOOKUP_SIZE;
		skip = (dp_djb_hash(&lbval->back_end_ips[i]) % (DP_LB_MAGLEV_LOOKUP_SIZE - 1)) + 1;

		for (j = 0; j < DP_LB_MAGLEV_LOOKUP_SIZE; j++)
			permutation[i * DP_LB_MAGLEV_LOOKUP_SIZE + j] = (offset + j * skip) % DP_LB_MAGLEV_LOOKUP_SIZE;
	}
	return permutation;
}

static __rte_always_inline bool dp_maglev_populate_iteration(struct lb_value *lbval, int *permutation, int *next, int *num)
{
	int i, j, pos;

	for (i = 0; i < lbval->back_end_cnt; i++) {
		for (j = next[i]; j < DP_LB_MAGLEV_LOOKUP_SIZE; j++) {
			pos = permutation[i * DP_LB_MAGLEV_LOOKUP_SIZE + j];
			next[i]++;
			if (lbval->maglev_hash[pos] == DP_MAGLEV_POS_FREE) {
				lbval->maglev_hash[pos] = (int16_t)i;
				(*num)++;
				if (*num == DP_LB_MAGLEV_LOOKUP_SIZE)
					return false;
				break;
			}
		}
	}
	return true;
}

static int dp_maglev_populate(struct lb_value *lbval, int *permutation)
{
	int *next = rte_zmalloc("maglev_hash", lbval->back_end_cnt * sizeof(int), RTE_CACHE_LINE_SIZE);
	int num = 0;

	if (!next) {
		DPS_LOG_ERR("Maglev hash memory allocation failed");
		return DP_ERROR;
	}

	for (int i = 0; i < DP_LB_MAGLEV_LOOKUP_SIZE; i++)
		lbval->maglev_hash[i] = DP_MAGLEV_POS_FREE;

	while (dp_maglev_populate_iteration(lbval, permutation, next, &num))
		;

	/* In case there was a non-filled spot, fill it randomly */
	for (int i = 0; i < DP_LB_MAGLEV_LOOKUP_SIZE; i++)
		if (lbval->maglev_hash[i] == DP_MAGLEV_POS_FREE)
			lbval->maglev_hash[i] = (int16_t)(i % lbval->back_end_cnt);

	rte_free(next);
	return DP_OK;
}

static int dp_maglev_calc_hash_lookup_table(struct lb_value *lbval)
{
	int *permutation = dp_maglev_permutation(lbval);
	int ret = DP_OK;

	if (!permutation)
		return DP_ERROR;

	if (DP_FAILED(dp_maglev_populate(lbval, permutation))) {
		DPS_LOG_WARNING("Loadbalancer Maglev population failed");
		ret = DP_ERROR;
	}

	rte_free(permutation);
	return ret;
}

static bool dp_is_ipv6_greater(const union dp_ipv6 *ip1, const union dp_ipv6 *ip2)
{
	for (size_t i = 0; i < sizeof(ip1->bytes); ++i) {
		if (ip1->bytes[i] < ip2->bytes[i])
			return false;
		if (ip1->bytes[i] > ip2->bytes[i])
			return true;
	}
	return false;
}

static void dp_shift_back_end_ips(union dp_ipv6 ips[], int start_pos, int end_pos, bool shift_up)
{
	int i;

	if (shift_up)
		for (i = end_pos; i > start_pos; i--)
			dp_copy_ipv6(&ips[i], &ips[i - 1]);
	else
		for (i = start_pos; i < end_pos; i++)
			dp_copy_ipv6(&ips[i], &ips[i + 1]);
}

int dp_add_maglev_backend(struct lb_value *lbval, const union dp_ipv6 *back_ip)
{
	int i, insert_pos = lbval->back_end_cnt;

	if (lbval->back_end_cnt >= DP_LB_MAX_IPS_PER_VIP)
		return DP_ERROR;

	/* Find the correct position to insert the new back ip */
	for (i = 0; i < lbval->back_end_cnt; i++) {
		if (dp_is_ipv6_greater(&lbval->back_end_ips[i], back_ip)) {
			insert_pos = i;
			break;
		}
	}

	dp_shift_back_end_ips(lbval->back_end_ips, insert_pos, lbval->back_end_cnt, DP_SHIFT_UP);
	dp_copy_ipv6(&lbval->back_end_ips[insert_pos], back_ip);
	lbval->back_end_cnt++;

	return dp_maglev_calc_hash_lookup_table(lbval);
}

int dp_delete_maglev_backend(struct lb_value *lbval, const union dp_ipv6 *back_ip)
{
	static union dp_ipv6 zero_ipv6 = { 0, };
	int i;

	for (i = 0; i < lbval->back_end_cnt; i++) {
		if (dp_ipv6_match(&lbval->back_end_ips[i], back_ip)) {
			dp_shift_back_end_ips(lbval->back_end_ips, i, lbval->back_end_cnt - 1, DP_SHIFT_DOWN);
			dp_copy_ipv6(&lbval->back_end_ips[lbval->back_end_cnt - 1], &zero_ipv6);
			lbval->back_end_cnt--;
			break;
		}
	}

	if (lbval->back_end_cnt == 0)
		return DP_OK;
	else
		return dp_maglev_calc_hash_lookup_table(lbval);
}

