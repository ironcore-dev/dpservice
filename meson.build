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
pytest = find_program('pytest', required : false)
scapy = find_program('scapy', required : false)

if not pytest.found()
  message('Without pytest, the tests can not be run')
endif

if not scapy.found()
  message('Without scapy, the tests can not be run')
endif

inc = include_directories('include')

subdir('proto')
subdir('include')
subdir('src')
subdir('test')
test('test-ipip', files('test/run_test'), args : [meson.current_build_dir(), 'ipip'], is_parallel : false, timeout : 35)
test('test-geneve', files('test/run_test'), args : [meson.current_build_dir(), 'geneve'],  is_parallel : false)

run_target('cppcheck', command : ['cppcheck', '--project=' + 
  join_paths(meson.build_root(), 'compile_commands.json')])

