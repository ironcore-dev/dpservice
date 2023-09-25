graphtrace_client_sources = [
  'dp_graphtrace.c',
  '../../src/dp_error.c',
  '../../src/monitoring/dp_graphtrace_shared.c',
]
executable('dp_graphtrace', graphtrace_client_sources,
  include_directories: [includes],
  dependencies: [dpdk_dep] )
