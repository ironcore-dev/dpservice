dpservice_dump_sources = [
  'main.c',
  '../common/dp_secondary_eal.c',
  '../../src/dp_argparse.c',
  '../../src/dp_error.c',
  '../../src/monitoring/dp_graphtrace_shared.c',
  '../../src/monitoring/dp_pcap.c',
]

executable('dpservice-dump',
  sources: [ dpservice_dump_sources, version_h ],
  include_directories: [includes],
  dependencies: [dpdk_dep, pcap_dep] )
