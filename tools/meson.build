grpc_client_sources = ['dp_grpc_client.cpp']

executable('dp_grpc_client', grpc_client_sources, grpc_generated,
  dependencies: [proto_dep, grpc_dep, grpccpp_dep] )

subdir('dp_graphtrace')
