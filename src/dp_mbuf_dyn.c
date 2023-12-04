// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include "dp_mbuf_dyn.h"

rte_atomic32_t dp_pkt_id_counter = {0};
