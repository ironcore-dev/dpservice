project('dp_service', 'c', 'cpp',
  default_options : ['c_args=-Wno-deprecated-declarations', 'cpp_args=-fpermissive'],
  version : '0.0.1',
  license : 'MIT')
add_global_arguments('-DDEBUG=true', language : 'c')
dpdk_dep = dependency('libdpdk', version : '>=21.11.0')
proto_dep = dependency('protobuf', version : '>=3.12.4')
grpc_dep = dependency('grpc', version : '>=10.0.0')
grpccpp_dep = dependency('grpc++', version : '>=1.30.2')
thread_dep = dependency('threads')

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
test('test', files('test/run_test'), args : [meson.current_build_dir()])

run_target('cppcheck', command : ['cppcheck', '--project=' + 
  join_paths(meson.build_root(), 'compile_commands.json')])

