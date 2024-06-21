// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#ifndef _DP_REFCOUNT_H_
#define _DP_REFCOUNT_H_

#include <rte_atomic.h>
#include <rte_debug.h>

#ifdef __cplusplus
extern "C" {
#endif

struct dp_ref {
	rte_atomic32_t refcount;
	void (*release)(struct dp_ref *dpref);
	bool valid;
};

static inline void dp_ref_init(struct dp_ref *ref, void (*release)(struct dp_ref *dpref))
{
	rte_atomic32_set(&ref->refcount, 1);
	ref->release = release;
	ref->valid = true;
}

static inline void dp_ref_inc(struct dp_ref *ref)
{
	RTE_VERIFY(ref->valid);
	RTE_VERIFY(rte_atomic32_read(&ref->refcount));
	rte_atomic32_add(&ref->refcount, 1);
}

static inline void dp_ref_dec(struct dp_ref *ref)
{
	RTE_VERIFY(ref->valid);
	if (rte_atomic32_dec_and_test(&ref->refcount))
		ref->release(ref);
}

static inline bool dp_ref_dec_and_chk_freed(struct dp_ref *ref)
{
	RTE_VERIFY(ref->valid);
	if (rte_atomic32_dec_and_test(&ref->refcount)) {
		ref->release(ref);
		return true;
	} else {
		return false;
	}
}

#ifdef __cplusplus
}
#endif
#endif /* _DP_REFCOUNT_H_ */
