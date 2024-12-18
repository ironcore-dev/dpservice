// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include "common_vnf.h"

const char *get_str_vnftype(enum dp_vnf_type type)
{
	switch (type) {
	case DP_VNF_TYPE_UNDEFINED:
		return "none";
	case DP_VNF_TYPE_LB_ALIAS_PFX:
		return "lb_pfx";
	case DP_VNF_TYPE_ALIAS_PFX:
		return "pfx";
	case DP_VNF_TYPE_LB:
		return "lb";
	case DP_VNF_TYPE_VIP:
		return "vip";
	case DP_VNF_TYPE_NAT:
		return "nat";
	case DP_VNF_TYPE_INTERFACE_IP:
		return "iface";
	}
	return "?";
}
