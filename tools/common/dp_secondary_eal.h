// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#ifndef __DP_SECONDARY_EAL_H__
#define __DP_SECONDARY_EAL_H__

#ifdef __cplusplus
extern "C" {
#endif

#define DP_SECONDARY_FILE_PREFIX_DEFAULT ""

int dp_secondary_eal_init(const char *file_prefix);

void dp_secondary_eal_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif
