#ifndef _DP_DEBUG_H_
#define _DP_DEBUG_H_

#ifdef __cplusplus
extern "C" {
#endif

#define RTE_ETHER_ADDR_PRT_FMT     "%02X:%02X:%02X:%02X:%02X:%02X"
#define RTE_ETHER_ADDR_BYTES(mac_addrs) ((mac_addrs)->addr_bytes[0]), \
                        ((mac_addrs)->addr_bytes[1]), \
                        ((mac_addrs)->addr_bytes[2]), \
                        ((mac_addrs)->addr_bytes[3]), \
                        ((mac_addrs)->addr_bytes[4]), \
                        ((mac_addrs)->addr_bytes[5])


void print_addr(uint8_t data_arr[])
{
    for (int i=0;i<16;i++)
    {
        printf("0x%02x ", data_arr[i]);
    }
    printf("\n");
}

#ifdef __cpluscplus
}
#endif
#endif
