grpc_client_sources = ['dp_grpc_client.cpp']

executable('dp_grpc_client', grpc_client_sources, grpc_generated,
  dependencies : [proto_dep, grpc_dep, grpccpp_dep] )

common_args = [ '--build-path='+meson.build_root() ]
pytest_dir = join_paths(meson.source_root(), 'test')

redundancy_tests = [ join_paths(pytest_dir, 'test_encap.py') ]

tunnels = [ 'ipip', 'geneve' ]
foreach tunnel : tunnels
  test('Base tests', pytest, suite: tunnel, is_parallel: false, timeout: 60,
    args: [ common_args, '--tun-opt='+tunnel, pytest_dir ])
  test('Port redundancy', pytest, suite: tunnel, is_parallel: false, timeout: 15,
    args: [ common_args, '--tun-opt='+tunnel, '--port-redundancy', redundancy_tests ])
endforeach
