clnt_sources = ['../proto/dpdk.grpc.pb.cc', '../proto/dpdk.pb.cc', 'dp_grpc_client.cpp']

executable('dp_grpc_client', clnt_sources, include_directories : proto_inc,
			dependencies : [proto_dep, grpc_dep, grpccpp_dep] )