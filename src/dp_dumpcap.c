#include <unistd.h>  // usleep()
#include <fcntl.h>
#include <pcap/pcap.h>

#include <rte_common.h>
#include <rte_eal.h>
#include <rte_debug.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>  // TODO only if not encapsulated by a printer

#include "monitoring/dp_pdump_client.h"

// TODO this could be dona via assign!
// EAL needs writable arguments (both the string and the array!)
// therefore convert them from literals and remember them for freeing later
static const char *eal_arg_strings[] = {
	"dp_dumpcap", "-l", "0", /*"-a", "0000:01:00.0", "-a", "0000:01:00.1", */ "--no-pci", "--proc-type", "secondary", "--log-level", "8"
	// TODO this seems to work even with wrong arguments for NICs, so maybe carefully ignore errors?
	// TODO or just use the new argparser and create this as a part of dp_service
};
static char *eal_args_mem[RTE_DIM(eal_arg_strings)];
static char *eal_args[RTE_DIM(eal_args_mem)];

static int eal_init()
{
	for (uint i = 0; i < RTE_DIM(eal_arg_strings); ++i) {
		eal_args[i] = eal_args_mem[i] = strdup(eal_arg_strings[i]);
		if (!eal_args[i]) {
			fprintf(stderr, "Cannot allocate EAL arguments\n");
			for (uint j = 0; j < RTE_DIM(eal_args_mem); ++j)
				free(eal_args_mem[j]);
			return -1;
		}
	}
	return rte_eal_init(RTE_DIM(eal_args), eal_args);
}

static void eal_cleanup()
{
	rte_eal_cleanup();
	for (uint i = 0; i < RTE_DIM(eal_args_mem); ++i)
		free(eal_args_mem[i]);
}


static int dump_loop(struct dp_pdump_client *pdump, pcap_dumper_t *dumper)
{
	// TODO encapsulate so we do not directly touch ring/mempool here?

	// TODO Ctrl-C
	for (;;) {
		// TODO burst of course!
		void *obj;
		if (rte_ring_dequeue(pdump->ringbuf, &obj) < 0) {  // TODO test ENOENT otherwise fail?
			printf("No packets, wait 250ms\r");
			fflush(stdout);
			usleep(250000);
			continue;
		}
		struct rte_mbuf *pkt = (struct rte_mbuf *)obj;
		printf("Received '%p'\n", pkt);

		// TODO  better, this is just a test copy
		// TODO document this temp data shenanigans
		uint8_t temp_data[1500];
		struct pcap_pkthdr header;

		gettimeofday(&header.ts, NULL);
		header.len = rte_pktmbuf_pkt_len(pkt);
		header.caplen = RTE_MIN(header.len, 1500);

		pcap_dump((u_char *)dumper, &header, rte_pktmbuf_read(pkt, 0, header.caplen, temp_data));
		// TODO test only! perf!!! -> Ctrl+c
		if (pcap_dump_flush(dumper))
			fprintf(stderr, "flush failed\n");
		// ---


		rte_mempool_put(pdump->mempool, obj);
	}
	return 0;
}

int main(int argc, char **argv)
{
	struct dp_pdump_client pdump;
	int retcode = 0;

	if (eal_init() < 0) {
		fprintf(stderr, "Cannot init EAL\n");
		return 1;
	}
	// TODO hmm this starts even without DP_service actually running!

	// TODO killing service does not bring this down!

	// TODO Ctrl-C
	// !!! especially since we need to disconnect!

	// TODO stdout support?
	// TODO file access mode!
	// TODO argument for file
	// TODO rename
	int fd = open("/tmp/testdump", O_WRONLY | O_CREAT, 0644);
	if (fd < 0) {
		// TODO better
		fprintf(stderr, "Cannot open output file\n");
		eal_cleanup();
		return 1;
	}

	pcap_t *pcap;
	// TODO why this format? 10Mb? Nano precision?
	// TODO SNAPLEN?? should be an argument anyway
	pcap = pcap_open_dead_with_tstamp_precision(DLT_EN10MB, 1500, PCAP_TSTAMP_PRECISION_NANO);
	if (!pcap)  // TODO
		rte_exit(EXIT_FAILURE, "pcap_open_dead failed\n");

	pcap_dumper_t *dumper;
	dumper = pcap_dump_fopen(pcap, fdopen(fd, "w"));
	if (!dumper)
		rte_exit(EXIT_FAILURE, "pcap_dump_fopen failed: %s\n", pcap_geterr(pcap));
	// TODO OMG encapsulate!

	// TODO omg refactor this mess

	// TODO refactor this
	if (dp_pdump_connect(&pdump) < 0) {
		fprintf(stderr, "Cannot connect to service\n");
		retcode = 1;
	} else {
		if (argc < 2) {
			// list only
			printf("Available interfaces:\n");
			struct dp_pdump_shmem *shmem = (struct dp_pdump_shmem *)pdump.memzone->addr;  // TODO aargh encapsulate
			for (uint i = 0; i < shmem->nb_ifaces; ++i) {
				struct dp_pdump_iface *iface = &shmem->ifaces[i];
				printf("\t%u: '%s'\n", iface->port_id, iface->port_name);
			}
		} else {
			// TODO argument/switch
			uint16_t port_id = *argv[1]-'0';  // TODO omg :)
			if (dp_pdump_connect_port(&pdump, port_id) < 0) {
				fprintf(stderr, "Error connecting to port %u\n", port_id);
				retcode = 1;
			} else {
				printf("Listening on port %u\n", port_id);
				if (dump_loop(&pdump, dumper) < 0) {
					fprintf(stderr, "Dumping failed\n");
					retcode = 1;
				}
			}
		}
	}

	pcap_close(pcap);
	pcap_dump_close(dumper);
	close(fd);

	eal_cleanup();

	return retcode;
}
