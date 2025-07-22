// SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#ifndef __INCLUDE_DP_SYNC_H__
#define __INCLUDE_DP_SYNC_H__

#include "dp_nat.h"

// TODO rename to dp_sync_send_*?

int dp_sync_create_nat(const struct netnat_portmap_key *portmap_key,
					   const struct netnat_portoverload_tbl_key *portoverload_key);

int dp_sync_delete_nat(const struct netnat_portmap_key *portmap_key,
					   const struct netnat_portoverload_tbl_key *portoverload_key);

#endif
