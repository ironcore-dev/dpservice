#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

#
# Use as /usr/local/sbin/dp-prepare.sh
#

OPT_MULTIPORT=false

BLUEFIELD_IDENTIFIERS=("MT_0000000543" "MT_0000000541")
MAX_NUMVFS_POSSIBLE=126
NUMVFS_DESIRED=126
CONFIG="/tmp/dp_service.conf"
IS_X86_WITH_BLUEFIELD=false
IS_ARM_WITH_BLUEFIELD=false
IS_X86_WITH_MLX=false
CONFIG_ONLY=false
OPT_VFIO_AUTO_BIND=false
VFIO_BIND_ONLY=false

function log() {
	echo "$(date +"%Y-%m-%d_%H-%M-%S-%3N") $1"
}

function err() {
	echo "$(date +"%Y-%m-%d_%H-%M-%S-%3N") ERROR: $1" 1>&2
	exit 1
}

function get_pfs() {
	readarray -t devs < <(devlink -js dev | jq -r '.dev | keys[] | select(startswith("pci/")) | sub("pci/"; "")')
}

function detect_card_and_arch_type() {
	local pf="${devs[0]}"
	local is_bluefield=false
	local devlink_info
	devlink_info=$(devlink -js dev info "pci/$pf")

	for id in "${BLUEFIELD_IDENTIFIERS[@]}"; do
		if echo "$devlink_info" | jq -e '.. | strings | select(. == "'"$id"'")' > /dev/null; then
			is_bluefield=true
			log "Detected BlueField card with identifier $id on pf: $pf"
			break
		fi
	done

	local arch=$(uname -m)
	case $arch in
		x86_64)
			log "Architecture is AMD/Intel 64-bit"
			;;
		aarch64)
			log "Architecture is ARM 64-bit"
			;;
		*)
			err "Unsupported architecture: $arch"
			;;
	esac

	if ! $is_bluefield; then
		log "Detected Mellanox card on pf: $pf"
	fi

	if [[ "$arch" = "aarch64" ]] && [[ "$is_bluefield" = "true" ]]; then
		log "Detected system is ARM architecture with Bluefield card"
		IS_ARM_WITH_BLUEFIELD=true
	fi

	if [[ "$arch" = "x86_64" ]] && [[ "$is_bluefield" = "false" ]]; then
		log "Detected system is AMD/Intel 64-bit architecture with Mellanox card"
		IS_X86_WITH_MLX=true
	fi

	if [[ "$arch" = "x86_64" ]] && [[ "$is_bluefield" = "true" ]]; then
		log "Detected system is AMD/Intel 64-bit architecture with Bluefield card"
		IS_X86_WITH_BLUEFIELD=true
	fi
}

function validate() {
	if ! command -v devlink &> /dev/null; then
		err "devlink not available, exiting"
	fi
	if ! command -v jq &> /dev/null; then
		err "jq not available, exiting"
	fi
}

function validate_pf() {

	if [[ "$IS_ARM_WITH_BLUEFIELD" == "true" && "$OPT_MULTIPORT" == "true" ]]; then
		err "Multiport eswitch mode is not yet supported for BlueField card on ARM"
	fi

	if [[ "$IS_ARM_WITH_BLUEFIELD" == "true" ]]; then
		log "Skipping PF validation for BlueField card on ARM"
		return
	fi

	# we check if sr-iov is enabled and the dev is using the mlx5 driver
	unset valid_devs
	for pf in "${devs[@]}"; do
		log "check pf $pf"
		if [ ! -f "/sys/bus/pci/devices/$pf/sriov_numvfs" ]; then
			log "pf $pf doesn't support sriov, excluding"
			continue
		fi
		if [ ! -L "/sys/bus/pci/drivers/mlx5_core/$pf" ]; then
			log "pf $pf is not using the proper driver, excluding"
			continue
		fi
		echo "pf $pf is valid"
		valid_devs+=( $pf )
	done
	devs=("${valid_devs[@]}")
}

process_switchdev_mode() {
	local pf=$1

	log "enabling switchdev for $pf"
	if ! devlink dev eswitch set "pci/$pf" mode switchdev; then
		err "can't set eswitch mode"
	fi
	log "now waiting for everything to settle"
	udevadm settle
}

process_multiport_eswitch_mode() {
	local pf=$1

	log "enabling multiport eswitch mode for $pf"
	if ! devlink dev param set "pci/$pf" name esw_multiport value true cmode runtime; then
		err "can't enable multiport eswitch mode"
	fi
	log "now waiting for everything to settle"
	udevadm settle
}

function vfio_bind() {
	local pf0="${devs[0]}"

	lsmod | grep -q '^vfio_pci' || {
		log "vfio-pci module not loaded, loading it"	
		modprobe vfio-pci
	}

	numvfs=$(cat /sys/bus/pci/devices/$pf0/sriov_numvfs)
	vf_offset=$(cat /sys/bus/pci/devices/$pf0/sriov_offset)

	vf_in_block_count=0
	vf_block_count=0
	vf_block_hex_index=0

	modified_pci=${pf0::-3}

	# pci address of vfs are organized in a block of 8
	# e.g., 3b:00.0 ... 3b:00.7, 3b:01.0 ... 3b:01.7, etc.
	for i in $(seq $vf_offset $((vf_offset + numvfs - 1))); do
		vf_in_block_count=$(($i%8))
		if [ $vf_in_block_count -eq 0 ]; then
			vf_block_count=$[$vf_block_count + 1]
			vf_block_hex_index=$(printf '%x' $vf_block_count)
		fi
		digits=${#vf_block_hex_index}
		if [ $digits -eq 2 ]; then
			modified_pci=${pf0::-4}
		fi

		vf_pci_addr=$modified_pci$vf_block_hex_index"."$vf_in_block_count

		echo 'vfio-pci' > /sys/bus/pci/devices/$vf_pci_addr/driver_override
		echo $vf_pci_addr > /sys/bus/pci/drivers/vfio-pci/bind
		log "VFs bound to vfio-pci driver"
	done

	sleep 1
}

function create_vf() {
	local pf0="${devs[0]}"
	local pf1="${devs[1]}"

	if [[ "$OPT_MULTIPORT" == "true" && "$NUMVFS_DESIRED" -eq "$MAX_NUMVFS_POSSIBLE" ]]; then
		NUMVFS_DESIRED=$((NUMVFS_DESIRED - 1))
	fi

	if [[ "$IS_ARM_WITH_BLUEFIELD" == "true" ]]; then
		actualvfs=$NUMVFS_DESIRED
		log "Skipping VF creation for BlueField card on ARM"
		# enable switchdev mode, this operation takes most time
		process_switchdev_mode "$pf0"
		return
	fi

	if [[ "$CONFIG_ONLY" == "true" ]]; then
		actualvfs=$(cat /sys/bus/pci/devices/$pf0/sriov_numvfs)
		log "Skipping VF creation as requested"
		return
	fi

	if [[ "$VFIO_BIND_ONLY" == "true" ]]; then
		log "Skipping VF creation as requested, binding VFs to vfio-pci driver"
		vfio_bind
		actualvfs=$(cat /sys/bus/pci/devices/$pf0/sriov_numvfs)
		return
	fi

	# we disable automatic binding so that VFs don't get created, saves a lot of time
	# plus we don't need to unbind them before enabling switchdev mode
	log "disabling automatic binding of VFs on pf0 '$pf0'"
	echo 0 > /sys/bus/pci/devices/$pf0/sriov_drivers_autoprobe

	if [[ "$IS_X86_WITH_MLX" == "true" || "$IS_X86_WITH_BLUEFIELD" == "true" ]]; then
		# enable switchdev mode, this operation takes most time
		log "Enabling switchdev mode for MLX or BlueField card on x86"
		if [[ "$OPT_MULTIPORT" == "true" ]]; then
			for pf in "${devs[@]}"; do
				process_switchdev_mode "$pf"
			done
		else
			process_switchdev_mode "$pf0"
		fi
	fi

	if [[ "$OPT_MULTIPORT" == "true" ]]; then
		for pf in "${devs[@]}"; do
			process_multiport_eswitch_mode "$pf"
		done
	fi

	# calculating amount of VFs to create, 126 if more are available, or maximum available
	totalvfs=$(cat /sys/bus/pci/devices/$pf0/sriov_totalvfs)
	actualvfs=$((NUMVFS_DESIRED<totalvfs ? NUMVFS_DESIRED : totalvfs))
	log "creating $actualvfs virtual functions"
	echo $actualvfs > /sys/bus/pci/devices/$pf0/sriov_numvfs

	if [[ "$OPT_VFIO_AUTO_BIND" == "true" ]]; then
		log "Binding VFs to vfio-pci driver"
		vfio_bind
	else
		log "Skipping VF binding to vfio-pci driver"
	fi
}


get_raw_vf_pattern() {
	local dev=$1
	devlink -js port | \
		jq -r --arg dev "$dev" '.port | to_entries[] | select(.key | startswith("pci/" + $dev)) | select(.value.flavour=="pcivf") | .value.netdev' | \
		sed -rn 's/(.*[a-z_])[0-9]{1,3}$/\1/p' | \
		uniq
}

function get_pattern() {
	local dev=$1
	local pattern

	if [[ "$IS_ARM_WITH_BLUEFIELD" == "true" ]]; then
		local timeout_seconds=120
		local interval_seconds=2
		local end_time=$(( $(date +%s) + timeout_seconds ))

		while [ $(date +%s) -lt $end_time ]; do
			pattern=$(get_raw_vf_pattern "$dev")
			if [ -n "$pattern" ]; then
				if [ $(wc -l <<< "$pattern") -eq 1 ]; then
					sleep $interval_seconds
					echo "$pattern"
					return
				fi
			fi
			sleep $interval_seconds
		done
		err "timed out after ${timeout_seconds}s waiting for the vf pattern for $dev"
	else
		pattern=$(get_raw_vf_pattern "$dev")
		if [ -z "$pattern" ]; then
			err "can't determine the vf pattern for $dev"
		elif [ $(wc -l <<< "$pattern") -ne 1 ]; then
			err "multiple vf patterns found for $dev"
		fi
		echo "$pattern"
	fi
}

function get_ifname() {
	local port_idx=$1
	devlink -js port | jq -r --argjson idx "$port_idx" '.port | .[] | select(.flavour=="physical" and .port==$idx) | .netdev'
}

function get_ipv6() {
	local ip_json
	ip_json=$(ip -js -6 addr show lo)

	if [ -z "$ip_json" ]; then
		err "Could not retrieve address information for interface 'lo'."
		return 1
	fi

	#   1. Have a "global" scope.
	#   2. Have a prefix length of 64 or more.
	#   3. Must be in Globally Unique Address (GUA) range (2 or 3).
	local global_address
	global_address=$(echo "$ip_json" | jq -r '
		.[0].addr_info[]
		| select(
			.scope == "global" and
			.prefixlen >= 64 and
			(.local | test("^(2|3)"))
		)
		| .local' | head -n 1)

	if [ -n "$global_address" ]; then
		echo "$global_address"
		return
	fi

	err "No Global Unicast IPv6 address with prefix >= 64 found on 'lo'."
}

function make_config() {
	conf_pf0="$(get_ifname 0)"
	conf_pf1="$(get_ifname 1)"
	conf_vf_pattern="$(get_pattern "${devs[0]}")"
	conf_ipv6="$(get_ipv6)"

	{ echo "# This has been generated by prepare.sh"
	echo "no-stats"
	echo "pf0 $conf_pf0"
	echo "pf1 $conf_pf1"
	echo "vf-pattern $conf_vf_pattern"
	echo "ipv6 $conf_ipv6"
	if [[ "$OPT_MULTIPORT" == "true" ]]; then
		echo "a-pf0 ${devs[0]},class=rxq_cqe_comp_en=0,rx_vec_en=1,dv_flow_en=2,dv_esw_en=1,fdb_def_rule_en=2,representor=pf[0-1]vf[0-$[$actualvfs-1]]"
		echo "multiport-eswitch"
	else
		echo "a-pf0 ${devs[0]},class=rxq_cqe_comp_en=0,rx_vec_en=1,representor=pf[0]vf[0-$[$actualvfs-1]]"
		echo "a-pf1 ${devs[1]},class=rxq_cqe_comp_en=0,rx_vec_en=1"
	fi; } > "$CONFIG"

	if [[ "$OPT_MULTIPORT" == "true" ]]; then
		log "dpservice configured in multiport-eswitch mode"
	else
		log "dpservice configured in normal mode"
	fi
}

# main
CONFIG_EXISTS=false
if [[ -e $CONFIG ]]; then
	CONFIG_EXISTS=true
fi

while [[ $# -gt 0 ]]; do
	case $1 in
		--vfio-auto-bind)
			OPT_VFIO_AUTO_BIND=true
			;;
		--multiport-eswitch)
			OPT_MULTIPORT=true
			;;
		--force)
			CONFIG_EXISTS=false
			;;
		--config-only)
			CONFIG_ONLY=true
			;;
		--vfio-bind-only)
			VFIO_BIND_ONLY=true
			;;
		*)
			err "Invalid argument $1"
	esac
	shift
done

if [[ "$CONFIG_EXISTS" == "true" ]]; then
	log "File $CONFIG already exists, no changes made"
	exit 0
fi

validate
get_pfs
detect_card_and_arch_type
validate_pf
# Bluefield relies on host side creating VFs, so wait here for systemd to settle and dont rush with the next steps
if [[ "$IS_ARM_WITH_BLUEFIELD" == "true" ]]; then
	udevadm settle
fi
create_vf
make_config
