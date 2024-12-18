dpservice_inspect_sources = [
  'common_ip.c',
  'common_vnf.c',
  'inspect.c',
  'inspect_conntrack.c',
  'inspect_iface.c',
  'inspect_lb.c',
  'inspect_nat.c',
  'inspect_vnf.c',
  'inspect_vni.c',
  'main.c',
  '../../src/dp_argparse.c',
  '../../src/dp_error.c',
  '../../src/dp_ipaddr.c',
]

executable('dpservice-inspect',
  sources: [ dpservice_inspect_sources, version_h ],
  include_directories: [includes],
  dependencies: [dpdk_dep] )
