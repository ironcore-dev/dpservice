// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#ifndef __INSPECT_NAT_H__
#define __INSPECT_NAT_H__

#include "inspect.h"

int dp_inspect_init_dnat(struct dp_inspect_spec *out_spec, enum dp_inspect_output_format format);

int dp_inspect_init_snat(struct dp_inspect_spec *out_spec, enum dp_inspect_output_format format);

int dp_inspect_init_portmap(struct dp_inspect_spec *out_spec, enum dp_inspect_output_format format);

int dp_inspect_init_portoverload(struct dp_inspect_spec *out_spec, enum dp_inspect_output_format format);

#endif
