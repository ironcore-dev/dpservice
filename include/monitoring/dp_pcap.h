#ifndef __DP_PCAP_H__
#define __DP_PCAP_H__

#include <pcap/pcap.h>
#include <rte_mbuf.h>

#ifdef __cplusplus
extern "C" {
#endif

struct dp_pcap {
	pcap_t *pcap;
	pcap_dumper_t *dumper;
	char error[256];
};

int dp_pcap_init(struct dp_pcap *dp_pcap, const char *dump_path);
void dp_pcap_free(struct dp_pcap *dp_pcap);

void dp_pcap_dump(struct dp_pcap *dp_pcap, struct rte_mbuf *m, struct timeval *timestamp);

#ifdef __cplusplus
}
#endif
#endif
