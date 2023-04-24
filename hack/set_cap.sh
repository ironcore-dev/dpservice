#!/bin/sh

# NET_ADMIN for setting MAC, etc.
# NET_RAW to access NIC ports
# SYS_ADMIN for /proc/self/pagemap access
# SYS_RAWIO to be able to apply rte_flow rules in transfer mode
# TODO: docs mention this sometimes: IPC_LOCK for DMA memory pinning

# NOTICE: binaries with file capabilities have their effective IDs changed to 'root:root' in /proc/self
# therefore also DAC_OVERRIDE is needed to ignore /proc/self/pagemap (now root) permissions
# which is of course not ideal, so maybe another way is needed (run as root and drop down after init?)

if [ $# -ne 2 ]; then
	echo "Usage: $0 <root-binary> <user-binary-name>" 2>&1
	exit 1
fi

if [ ! -f "$1" ]; then
	echo "Specified binary does not exist: '$1'" 2>&1
	exit 1
fi

cp $1 $2 && sudo setcap cap_sys_rawio,cap_net_raw,cap_net_admin,cap_sys_admin,cap_dac_override=eip $2
