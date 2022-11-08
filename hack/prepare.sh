#!/bin/bash

CONF_FILE="/tmp/dp_service.conf"
PF0_NAME=""
PF0_PCI_ADDR=""
PF1_PCI_ADDR=""
NUM_VF=30
VF_START=2
NUM_PAGES=4

timestamp() {
    date +"%Y-%m-%d_%H-%M-%S-%3N"
}


exit_msg() {
    echo "$(timestamp): ERROR: $1" >&2
    exit 1
}


function detect_pfs() {
count=0
read_next=0
while read l1; do
    if [[ $l1 =~ physical ]]; then
        IFS=" "
        for i in $l1; do
            if [ $read_next -eq 1 ]; then
                read_next=0
                if [ $count -eq 0 ]; then
                    PF0_NAME=$i
                fi
                echo "pf"$count" "$i >> $CONF_FILE
                count=$[$count + 1]
            fi
            if [ "$i" = "netdev" ]; then
                read_next=1
            fi
            if [[ "$i" == "pci"* ]]; then
                IFS="/"
                for k in $i; do
                    if [ $count -eq 0 ]; then
                        if [[ "$k" == "0000:"* ]]; then
                            PF0_PCI_ADDR=$k
                            echo "$(timestamp): detected PF0 "$PF0_PCI_ADDR
                        fi
                    fi
                    if [ $count -eq 1 ]; then
                        if [[ "$k" == "0000:"* ]]; then
                            PF1_PCI_ADDR=$k
                            echo "$(timestamp): detected PF1 "$PF1_PCI_ADDR
                        fi
                    fi
                done
            fi
            IFS=" "
        done
        if [ $count -eq 2 ]; then
            break
        fi
    fi
done < <(devlink port)

if [ $count -ne 2 ]; then
    exit_msg "Need at least 2 PFs"
fi
}


function detect_vfs() {
count=0
read_next=0
while read l1; do
    if [[ $l1 =~ pcivf || $l1 =~ virtual ]]; then
        IFS=" "
        for i in $l1; do
            if [ $read_next -eq 1 ]; then
                read_next=0
                modified=${i::-1}
                echo "vf-pattern "$modified >> $CONF_FILE
                echo "$(timestamp): detected vf pattern "$modified
                count=$[$count + 1]
            fi
            if [ "$i" = "netdev" ]; then
                read_next=1
            fi
        done
        if [ $count -eq 1 ]; then
            break
        fi
    fi
done < <(devlink port)
}


function detect_ipv6() {
while read l1; do
    if [ "$l1" != "::1/128" ]; then
        modified=${l1::-4}
        echo "ipv6 "$modified >> $CONF_FILE
    fi
done < <(ip -6 -o addr show lo | awk '{print $4}')
}


function configure_vfs() {

if [ ! -f /sys/class/net/$PF0_NAME/device/sriov_totalvfs ] || [ ! -d /sys/bus/pci/drivers/mlx5_core ]; then
   exit_msg "Mellanox card with SR-IOV enabled is required"
fi

maxvfs=$(cat /sys/class/net/$PF0_NAME/device/sriov_totalvfs)
numvfs=$(cat /sys/class/net/$PF0_NAME/device/sriov_numvfs)
mod_vf_count=0
prefix_count=0

if [ $numvfs -eq 0 ]; then
    allowedvfs=$((maxvfs - VF_START))
    if [ "$allowedvfs" -lt "$NUM_VF" ]; then
        NUM_VF=$allowedvfs
    fi
    echo "$(timestamp): creating "$NUM_VF" VFs"
    echo $NUM_VF > /sys/class/net/$PF0_NAME/device/sriov_numvfs
    modified_pci=${PF0_PCI_ADDR::-3}
    sleep 1

    for ((i=$VF_START;i<=1+$NUM_VF;i+=1)); do
        mod_vf_count=$(($i%8))
        if [ $mod_vf_count -eq 0 ]; then
            prefix_count=$[$prefix_count + 1]
        fi
        echo $modified_pci$prefix_count"."$mod_vf_count > /sys/bus/pci/drivers/mlx5_core/unbind
    done
    sleep 2
    echo "$(timestamp): changing eswitch mode for "$PF0_PCI_ADDR" to switchdev"
    devlink dev eswitch set pci/$PF0_PCI_ADDR mode switchdev
    if [ $? -ne 0 ]; then
        echo "$(timestamp): reverting to 0 VFs"
        echo "0" > $numvfs_file
        exit_msg "Unable to set eswitch mode"
    fi
fi

}


function configure_hugepages() {
if [ -d /sys/kernel/mm/hugepages/hugepages-1048576kB ]; then
    numpages=$(cat /sys/kernel/mm/hugepages/hugepages-1048576kB/nr_hugepages)
    if [ $numpages -eq 0 ]; then
        echo $NUM_PAGES > /sys/kernel/mm/hugepages/hugepages-1048576kB/nr_hugepages
        mkdir -p /dev/hugepages1G
        mount -t hugetlbfs -o pagesize=1G none /dev/hugepages1G
    fi
elif [ -d /sys/kernel/mm/hugepages/hugepages-2048kB ]; then
    echo "$(timestamp): WARNING: Using 2MB hugepages only" >&2
    numpages=$(cat /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages)
    if [ $numpages -eq 0 ]; then
       echo $(($NUM_PAGES*512)) > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
       mkdir -p /dev/hugepages
       mount -t hugetlbfs -o pagesize=2M none /dev/hugepages
    fi
else
    exit_msg "No hugepage support"
fi
}


function prepare_melanox_param() {
PARAM=$[$NUM_VF - 1]
echo "a-pf0 "$PF0_PCI_ADDR",class=rxq_cqe_comp_en=0,rx_vec_en=1,representor=pf[0]vf[0-"$PARAM"]" >> $CONF_FILE
echo "a-pf1 "$PF1_PCI_ADDR",class=rxq_cqe_comp_en=0,rx_vec_en=1" >> $CONF_FILE
}


rm -f $CONF_FILE

echo "$(timestamp): detecting PFs"
detect_pfs
echo "$(timestamp): configuring VFs"
configure_vfs
echo "$(timestamp): configuring hugepages"
configure_hugepages
echo "$(timestamp): detecting VFs"
detect_vfs
echo "$(timestamp): detecting underlay ipv6 address"
detect_ipv6
echo "$(timestamp): calculating mellanox parameters"
prepare_melanox_param
echo "$(timestamp): all results written to "$CONF_FILE

exit 0
