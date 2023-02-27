pytest_dir = join_paths(meson.source_root(), 'test')

common_args = [ '--build-path='+meson.build_root() ]
if get_option('enable_virtual_services')
	common_args += '--virtsvc'
endif

redundancy_tests = []
redundancy_enabled_py = [ 'test_encap.py', 'test_virtsvc.py' ]
foreach py : redundancy_enabled_py
  redundancy_tests += join_paths(pytest_dir, py)
endforeach

# Geneve currently not supported
#tunnels = [ 'ipip', 'geneve' ]
tunnels = [ 'ipip' ]
foreach tunnel : tunnels
  test('Base tests', pytest, suite: tunnel, is_parallel: false, timeout: 60,
    args: [ common_args, '--tun-opt='+tunnel, pytest_dir ])
  test('Port redundancy', pytest, suite: tunnel, is_parallel: false, timeout: 15,
    args: [ common_args, '--tun-opt='+tunnel, '--port-redundancy', redundancy_tests ])
endforeach
