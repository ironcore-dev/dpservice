dpservice_dump_sources = [
  'main.c',
  '../../src/dp_error.c',
  '../../src/monitoring/dp_graphtrace_shared.c',
  '../../src/monitoring/dp_pcap.c',
]

executable('dpservice-dump', dpservice_dump_sources,
  include_directories: [includes],
  dependencies: [dpdk_dep, pcap_dep] )
