pytest_dir = join_paths(meson.source_root(), 'test')

common_args = [ '--build-path='+meson.build_root() ]
if get_option('enable_virtual_services')
	common_args += '--virtsvc'
endif

redundancy_tests = []
redundancy_enabled_py = [ 'test_encap.py', 'test_vf_to_pf.py', 'test_virtsvc.py' ]
foreach py : redundancy_enabled_py
  redundancy_tests += join_paths(pytest_dir, py)
endforeach

flow_timeout_test = join_paths(pytest_dir, 'xtratest_flow_timeout.py')

test('Base tests', pytest, suite: 'TAP', is_parallel: false, timeout: 60,
  args: [ common_args, pytest_dir ])
test('Port redundancy', pytest, suite: 'TAP', is_parallel: false, timeout: 15,
  args: [ common_args, '--port-redundancy', redundancy_tests ])
test('Flow timeout', pytest, suite: 'TAP', is_parallel: false, timeout: 30,
  args: [ common_args, '--fast-flow-timeout', flow_timeout_test ])
