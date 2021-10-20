project('dp_service', 'c',
  version : '0.0.1',
  license : 'MIT')
add_global_arguments('-DDEBUG=true', language : 'c')
dpdk_dep = dependency('libdpdk')

inc = include_directories('include')

subdir('include')
subdir('src')
