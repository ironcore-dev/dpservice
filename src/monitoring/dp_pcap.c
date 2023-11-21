#include "monitoring/dp_pcap.h"
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include "dp_error.h"

#define DP_PCAP_MTU 9100

// largest header is Ether + IPv6(underlay) + IPv4(with all options) + TCP(with all options)
// this adds up to 14 + 40 + 60 + 60
// adding a few more to round it up and be on the safe side
// this size should never result in actual data copy by rte_pktmbuf_read()
#define DP_PCAP_FILTER_MTU 256

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
	header.caplen = RTE_MIN(header.len, (uint32_t)sizeof(buffer));

	// rte_pktmbuf_read() can only fail if the buffer is too small, hence RTE_MIN() above
	pcap_dump((void *)dp_pcap->dumper, &header, rte_pktmbuf_read(m, 0, header.caplen, buffer));
}

int dp_compile_bpf(struct bpf_program *bpf, const char *pcap_filter)
{
	pcap_t *dummy_pcap;  // some pcap_t required for the BPF compilation
	int ret;

	// errors not logged here as the filter should have been verified by a client program
	dummy_pcap = pcap_open_dead(DLT_EN10MB, DP_PCAP_MTU);
	if (!dummy_pcap)
		return DP_ERROR;

	ret = pcap_compile(dummy_pcap, bpf, pcap_filter, /*optimize=*/1, PCAP_NETMASK_UNKNOWN);
	if (DP_FAILED(ret))
		ret = DP_ERROR;  // pcap uses its own set of negative values for errors

	pcap_close(dummy_pcap);

	return ret;
}

void dp_free_bpf(struct bpf_program *bpf)
{
	pcap_freecode(bpf);
}

bool dp_is_bpf_match(struct bpf_program *bpf, struct rte_mbuf *m)
{
	uint8_t buffer[DP_PCAP_FILTER_MTU];
	uint32_t len = rte_pktmbuf_pkt_len(m);
	struct pcap_pkthdr header = {
		.len = len,
		.caplen = RTE_MIN(len, (uint32_t)sizeof(buffer)),
		// timestamp left zero, not needed for filtering
	};

	// rte_pktmbuf_read() can only fail if the buffer is too small, hence RTE_MIN() above
	return pcap_offline_filter(bpf, &header, rte_pktmbuf_read(m, 0, header.caplen, buffer));
}
