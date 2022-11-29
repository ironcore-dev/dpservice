project('dp_service', 'c', 'cpp',
  default_options : ['c_args=-Wno-deprecated-declarations -Werror -Wno-format-truncation', 'cpp_args=-fpermissive'],
  version: run_command('cat', 'include/dp_version.h').stdout().strip().split(' ').get(2).split('"').get(1),
  license : 'MIT')
add_global_arguments('-DDEBUG=true', language : 'c')
dpdk_dep = dependency('libdpdk', version : '>=21.11.0')
proto_dep = dependency('protobuf')
grpc_dep = dependency('grpc')
grpccpp_dep = dependency('grpc++')
thread_dep = dependency('threads')
libuuid_dep = dependency('uuid')

protoc = find_program('protoc')
grpc_cpp = find_program('grpc_cpp_plugin')
if get_option('enable_tests')
  pytest = find_program('pytest')
  scapy = find_program('scapy')
endif
if get_option('enable_usermode')
  sudo = find_program('sudo')
  setcap = find_program('setcap')
endif

inc = include_directories('include')

subdir('proto')
subdir('include')
subdir('src')
if get_option('enable_tests')
  subdir('test')
endif

run_target('cppcheck', command : ['cppcheck', '--project=' + 
  join_paths(meson.build_root(), 'compile_commands.json')])
