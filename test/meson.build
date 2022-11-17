clnt_sources = ['dp_grpc_client.cpp']

executable('dp_grpc_client', clnt_sources, grpc_generated,
			dependencies : [proto_dep, grpc_dep, grpccpp_dep] )

common_args = [ '--build-path='+meson.build_root() ]
pytest_dir = join_paths(meson.source_root(), 'test')
tests = [ 'ipv6_nd', 'ipv6_dhcp6' ]
port_redundancy = true
redundant_tests = []
noredundant_tests = [ 'ipv6_ip6ip6' ]

if port_redundancy
	common_args += '--port-redundancy'
	tests += redundant_tests
	skip_tests = noredundant_tests
else
	tests += noredundant_tests
	skip_tests = redundant_tests
endif

foreach t : tests
	testfile = join_paths(pytest_dir, 'test_'+t+'.py')
	test(t, pytest, args: [ common_args, '--tun-opt=ipip', testfile ], suite: 'ipip', is_parallel : false)
	test(t, pytest, args: [ common_args, '--tun-opt=geneve', testfile ], suite: 'geneve', is_parallel : false)
endforeach

# Meson does not differentiate skipped and failed error results of pytest, so this is a way around it
foreach t : skip_tests
	test(t, sh, args: ['-c', 'exit 77'], suite: 'ipip')
	test(t, sh, args: ['-c', 'exit 77'], suite: 'geneve')
endforeach
