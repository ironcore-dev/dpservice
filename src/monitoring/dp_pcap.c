#include "monitoring/dp_pcap.h"
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include "dp_error.h"

#define DP_PCAP_MTU 9100

int dp_pcap_init(struct dp_pcap *dp_pcap, const char *dump_path)
{
	dp_pcap->error[0] = '\0';

	dp_pcap->pcap = pcap_open_dead(DLT_EN10MB, DP_PCAP_MTU);
	if (!dp_pcap->pcap) {
		snprintf(dp_pcap->error, sizeof(dp_pcap->error), "Cannot prepare pcap");
		return DP_ERROR;
	}

	dp_pcap->dumper = pcap_dump_open(dp_pcap->pcap, dump_path);
	if (!dp_pcap->dumper) {
		snprintf(dp_pcap->error, sizeof(dp_pcap->error), "%s", pcap_geterr(dp_pcap->pcap));
		pcap_close(dp_pcap->pcap);
		return DP_ERROR;
	}

	return DP_OK;
}

void dp_pcap_free(struct dp_pcap *dp_pcap)
{
	pcap_dump_close(dp_pcap->dumper);
	pcap_close(dp_pcap->pcap);
}


void dp_pcap_dump(struct dp_pcap *dp_pcap, struct rte_mbuf *m, struct timeval *timestamp)
{
	uint8_t buffer[DP_PCAP_MTU];
	struct pcap_pkthdr header;

	header.ts = *timestamp;
	header.len = rte_pktmbuf_pkt_len(m);
	header.caplen = RTE_MIN(header.len, sizeof(buffer));

	// rte_pktmbuf_read() can only fail if the buffer is too small, hence RTE_MIN() above
	pcap_dump((void *)dp_pcap->dumper, &header, rte_pktmbuf_read(m, 0, header.caplen, buffer));
}
