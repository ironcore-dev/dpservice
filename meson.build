project('dp_service', 'c', 'cpp',
  default_options : ['c_args=-Wno-deprecated-declarations', 'cpp_args=-fpermissive'],
  version : '0.0.1',
  license : 'MIT')
add_global_arguments('-DDEBUG=true', language : 'c')
dpdk_dep = dependency('libdpdk')
proto_dep = dependency('protobuf')
grpc_dep = dependency('grpc')
grpccpp_dep = dependency('grpc++')

protoc = find_program('protoc')
grpc_cpp = find_program('grpc_cpp_plugin')


grpc_pb_cc = custom_target('grpc_pb_cc',
  input: ['proto/dpdk.proto'],
  output: ['@BASENAME@.pb.cc'],
  command: [
    protoc,
	'--proto_path=../proto',
    '--cpp_out=../proto',
    '@INPUT@',
  ],
  build_by_default: true,
    install : true,
  install_dir : 'proto'
)

grpc_pb_h = custom_target('grpc_pb_h',
  input: ['proto/dpdk.proto'],
  output: ['@BASENAME@.pb.h'],
  command: [
    protoc,
	'--proto_path=../proto',
    '--cpp_out=../proto',
    '@INPUT@',
  ],
  build_by_default: true,
  install : true,
  install_dir : 'proto'
)

grpc_pb_cc2 = custom_target('grpc_pb_cc2',
  input: ['proto/dpdk.proto'],
  output: ['@BASENAME@.grpc.pb.cc'],
  command: [
    protoc,
	'--proto_path=../proto',
	'--grpc_out=../proto',
	'--plugin=protoc-gen-grpc=' + grpc_cpp.path(),
    '@INPUT@',
  ],
  build_by_default: true,
    install : true,
  install_dir : 'proto'
)

grpc_pb_h2 = custom_target('grpc_pb_h2',
  input: ['proto/dpdk.proto'],
  output: ['@BASENAME@.grpc.pb.h'],
  command: [
    protoc,
	'--proto_path=../proto',
	'--grpc_out=../proto',
	'--plugin=protoc-gen-grpc=' + grpc_cpp.path(),
    '@INPUT@',
  ],
  build_by_default: true,
    install : true,
  install_dir : 'proto'
)

inc = include_directories('include')
proto_inc = include_directories('proto')

subdir('include')
subdir('src')
subdir('test')
