#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

#
# Use as /usr/local/sbin/dp-prepare.sh
#

BLUEFIELD_IDENTIFIERS=("MT_0000000543")
NUMVFS=126
CONFIG="/tmp/dp_service.conf"
IS_BLUEFIELD=false

function log() {
	echo "$(date +"%Y-%m-%d_%H-%M-%S-%3N") $1"
}

function err() {
	echo "$(date +"%Y-%m-%d_%H-%M-%S-%3N") ERROR: $1" 1>&2
	exit 1
}

function get_pf() {
	readarray -t devs < <(devlink dev | awk -F/ '{print $2}')
}

function detect_card_type() {
	local pf="${devs[0]}"
	for id in "${BLUEFIELD_IDENTIFIERS[@]}"; do
		if devlink dev info pci/$pf | grep -q "$id"; then
			IS_BLUEFIELD=true
			log "Detected BlueField card with identifier $id on pf: $pf"
			break
		fi
	done

	if ! $IS_BLUEFIELD; then
		log "Detected Mellanox card on pf: $pf"
	fi
}

function validate() {
	# we check if we have devlink available
	if ! command -v devlink 2> /dev/null; then
		err "devlink not available, exiting"
	fi
}

function validate_pf() {
	if $IS_BLUEFIELD; then
		log "Skipping PF validation for BlueField card"
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

function create_vf() {
	if $IS_BLUEFIELD; then
		actualvfs=$NUMVFS
		log "Skipping VF creation for BlueField card"
		return
	fi

	local pf="${devs[0]}"
	# we disable automatic binding so that VFs don't get created, saves a lot of time
	# plus we don't need to unbind them before enabling switchdev mode
	log "disabling automatic binding of VFs on pf: $pf"
	echo 0 > /sys/bus/pci/devices/$pf/sriov_drivers_autoprobe

	# calculating amount of VFs to create, 126 if more are available, or maximum available
	totalvfs=$(cat /sys/bus/pci/devices/$pf/sriov_totalvfs)
	actualvfs=$((NUMVFS<totalvfs ? NUMVFS : totalvfs))
	log "creating $actualvfs virtual functions"
	echo $actualvfs > /sys/bus/pci/devices/$pf/sriov_numvfs

	# enable switchdev mode, this operation takes most time
	log "enabling switchdev for $pf"
	if ! devlink dev eswitch set pci/$pf mode switchdev; then
		log "can't set eswitch mode, setting VFs to 0"
		echo 0 > /sys/bus/pci/devices/$pf/sriov_numvfs
	fi
	log "now waiting for everything to settle"
	udevadm settle
}

function get_pattern() {
	local dev=$1
	pattern=$(devlink port | grep pci/$dev/ | grep "virtual\|pcivf" | awk '{print $5}' | sed -rn 's/(.*[a-z_])[0-9]{1,3}$/\1/p' | uniq)
	if [ -z "$pattern" ]; then
		err "can't determine the pattern for $dev"
	elif [ $(wc -l <<< "$pattern") -ne 1 ]; then
		err "multiple patterns found for $dev"
	fi
	echo "$pattern"
}

function get_ifname() {
	local dev=$1
	devlink port | grep pci/$dev/ | grep physical | awk '{ print $5}'
}

function get_ipv6() {
	# TODO: this needs to be done in a better way
	while read -r l1; do
		if [ "$l1" != "::1/128" ]; then
        		echo ${l1%/*}
			break
    		fi
	done < <(ip -6 -o addr show lo | awk '{print $4}')
}

function make_config() {
	: > "$CONFIG"
	{ echo "# This has been generated by prepare.sh"
	echo "no-stats";
	echo "pf0 $(get_ifname ${devs[0]})";
	echo "pf1 $(get_ifname ${devs[1]})";
	echo "vf-pattern $(get_pattern ${devs[0]})";
	echo "ipv6 $(get_ipv6)";
	echo "a-pf0 ${devs[0]},class=rxq_cqe_comp_en=0,rx_vec_en=1,representor=pf[0]vf[0-$[$actualvfs-1]]";
	echo "a-pf1 ${devs[1]},class=rxq_cqe_comp_en=0,rx_vec_en=1"; } >> "$CONFIG"
}

# main
if [ -e $CONFIG ]; then
    echo "File $CONFIG already exists"
    exit
fi

validate
get_pf
detect_card_type
validate_pf
create_vf
make_config

exit
