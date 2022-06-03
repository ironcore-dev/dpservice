#!/bin/bash
CONF_FILE="/tmp/dp_service.conf"
PF0_NAME=""
PF0_PCI_ADDR=""
PF1_PCI_ADDR=""
NUM_VF=6
VF_START=2
NUM_PAGES=4

function detect_pfs() {
count=0
read_next=0
while read l1 ;do 
   if [[ $l1 =~ physical ]];then     
      IFS=" "
      for i in $l1 ;do
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
           for k in $i ;do
               if [ $count -eq 0 ]; then
                   if [[ "$k" == "0000:"* ]]; then
                       PF0_PCI_ADDR=$k
                   fi
               fi
               if [ $count -eq 1 ]; then
                   if [[ "$k" == "0000:"* ]]; then
                       PF1_PCI_ADDR=$k
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

# Return an error, if we find less pfs then 2
if [ $count -ne 2 ]; then
     exit 1
fi
}

function detect_vfs() {
count=0
read_next=0
while read l1 ;do 
   if [[ $l1 =~ pcivf || $l1 =~ virtual ]];then     
      IFS=" "
      for i in $l1 ;do
         if [ $read_next -eq 1 ]; then
            read_next=0
            modified=${i::-1} 
            echo "vf-pattern "$modified >> $CONF_FILE
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

while read l1 ;do 
   if [ "$l1" != "::1/128" ]; then
      modified=${l1::-4}
      echo "ipv6 "$modified >> $CONF_FILE
   fi
done < <(ip -6 -o addr show lo | awk '{print $4}')

}

function configure_vfs() {

maxvfs=$(cat /sys/class/net/$PF0_NAME/device/sriov_totalvfs)
numvfs=$(cat /sys/class/net/$PF0_NAME/device/sriov_numvfs)

if [ $numvfs -eq 0 ]; then
    allowedvfs=$((maxvfs - VF_START))
    if [ "$allowedvfs" -lt "$NUM_VF" ]; then
       NUM_VF=$allowedvfs
    fi
    
    echo $NUM_VF | tee /sys/class/net/$PF0_NAME/device/sriov_numvfs
    modified_pci=${PF0_PCI_ADDR::-2}
    sleep 1
    for ((i=$VF_START;i<=1+$NUM_VF;i+=1)); do echo $modified_pci"."$i > /sys/bus/pci/drivers/mlx5_core/unbind; done
    sleep 2
    devlink dev eswitch set pci/$PF0_PCI_ADDR mode switchdev
fi

}

function configure_hugepages() {

numpages=$(cat /sys/kernel/mm/hugepages/hugepages-1048576kB/nr_hugepages)
if [ $numpages -eq 0 ]; then
    echo $NUM_PAGES > /sys/kernel/mm/hugepages/hugepages-1048576kB/nr_hugepages
    mkdir /dev/hugepages1G
    mount -t hugetlbfs -o pagesize=1G none /dev/hugepages1G
fi

}

function prepare_melanox_param() {

PARAM=$[$NUM_VF - 1]
echo "a-pf0 "$PF0_PCI_ADDR",class=rxq_cqe_comp_en=0,rx_vec_en=1,representor=pf[0]vf[0-"$PARAM"]" >> $CONF_FILE
echo "a-pf1 "$PF1_PCI_ADDR",class=rxq_cqe_comp_en=0,rx_vec_en=1" >> $CONF_FILE

}

rm -f $CONF_FILE
detect_pfs;
configure_vfs;
configure_hugepages;
detect_vfs;
detect_ipv6;
prepare_melanox_param;

exit 0;
