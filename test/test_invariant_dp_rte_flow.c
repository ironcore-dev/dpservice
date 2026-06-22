#include <check.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_ip.h>
#include <rte_icmp.h>

#include "dp_rte_flow.c"

/* We directly test dp_get_icmp_err_ip_hdr by constructing adversarial packets */

static struct rte_mempool *test_pool;

static struct rte_mbuf *create_icmp_err_packet(uint8_t ihl_value)
{
    struct rte_mbuf *m = rte_pktmbuf_alloc(test_pool);
    if (!m) return NULL;

    /* Outer IPv4 + ICMP header + embedded IPv4 (with crafted IHL) + 8 bytes L4 */
    size_t outer_ip_len = sizeof(struct rte_ipv4_hdr);
    size_t icmp_len = sizeof(struct rte_icmp_hdr);
    size_t inner_ip_len = sizeof(struct rte_ipv4_hdr);
    size_t l4_bytes = 8;
    size_t total = outer_ip_len + icmp_len + inner_ip_len + l4_bytes;

    char *data = rte_pktmbuf_append(m, total);
    if (!data) { rte_pktmbuf_free(m); return NULL; }
    memset(data, 0, total);

    struct rte_ipv4_hdr *outer_ip = (struct rte_ipv4_hdr *)data;
    outer_ip->version_ihl = (4 << 4) | 5;
    outer_ip->next_proto_id = IPPROTO_ICMP;
    outer_ip->total_length = rte_cpu_to_be_16(total);

    struct rte_icmp_hdr *icmp = (struct rte_icmp_hdr *)(data + outer_ip_len);
    icmp->icmp_type = DP_IP_ICMP_TYPE_ERROR;

    struct rte_ipv4_hdr *inner_ip = (struct rte_ipv4_hdr *)(data + outer_ip_len + icmp_len);
    inner_ip->version_ihl = (4 << 4) | (ihl_value & 0x0F);
    inner_ip->next_proto_id = IPPROTO_TCP;

    /* Fill L4 area with known pattern */
    memset(data + outer_ip_len + icmp_len + inner_ip_len, 0xAB, l4_bytes);

    return m;
}

START_TEST(test_icmp_err_ihl_bounds)
{
    /* Invariant: IHL values outside [5,15] or causing offset beyond packet must not
       result in out-of-bounds reads. Valid IHL=5 must succeed safely. */
    uint8_t ihl_values[] = {
        0,   /* exploit: IHL=0, offset=0 reads IP header as L4 ports */
        15,  /* boundary: IHL=15, offset=60 exceeds embedded data */
        5,   /* valid: IHL=5, offset=20 is correct */
    };
    int num = sizeof(ihl_values) / sizeof(ihl_values[0]);

    test_pool = rte_pktmbuf_pool_create("test_pool", 64, 0, 0, 2048, 0);
    ck_assert_ptr_nonnull(test_pool);

    for (int i = 0; i < num; i++) {
        struct rte_mbuf *m = create_icmp_err_packet(ihl_values[i]);
        ck_assert_ptr_nonnull(m);

        struct dp_icmp_err_ip_info err_info;
        memset(&err_info, 0, sizeof(err_info));

        /* The function must not crash or read OOB for any IHL value.
           For invalid IHL, it should either reject or safely handle. */
        int ret = dp_get_icmp_err_ip_hdr(m, &err_info);

        if (ihl_values[i] == 5) {
            /* Valid case: should succeed */
            ck_assert_int_eq(ret, 0);
        } else {
            /* Invalid IHL: function MUST reject (return error) to prevent OOB */
            ck_assert_int_ne(ret, 0);
        }

        rte_pktmbuf_free(m);
    }

    rte_mempool_free(test_pool);
}