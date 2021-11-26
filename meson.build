project('dp_service', 'c', 'cpp',
  default_options : ['c_args=-Wno-deprecated-declarations', 'cpp_args=-fpermissive'],
  version : '0.0.1',
  license : 'MIT')
add_global_arguments('-DDEBUG=true', language : 'c')
dpdk_dep = dependency('libdpdk')

inc = include_directories('include')

subdir('include')
subdir('src')
