grpc_generated = custom_target(
    'messages_generated',
    input: ['dpdk.proto'],
    output: ['@BASENAME@.pb.h', '@BASENAME@.pb.cc', '@BASENAME@.grpc.pb.h', '@BASENAME@.grpc.pb.cc'],
    command: [
        protoc,
        '--plugin=protoc-gen-grpc=' + grpc_cpp.path(),
        '--proto_path=@CURRENT_SOURCE_DIR@',
        '--cpp_out=@OUTDIR@',
        '--grpc_out=@OUTDIR@',
        '@INPUT@'
    ],
	install : true,
	install_dir : meson.source_root() + '/' + 'proto'
)