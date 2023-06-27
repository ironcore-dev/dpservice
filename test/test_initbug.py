from helpers import *

def test_init_bug(prepare_ipv4, grpc_client):
	grpc_client.addprefix(VM1.name, "1.2.3.0/24")
	prefix_list = grpc_client.listprefixes(VM1.name)
	assert len(prefix_list) == 1, \
		"List of prefixes should only contain one prefix"
	grpc_client.init()
	grpc_client.listprefixes(VM1.name)
	assert len(prefix_list) == 0, \
		"List of prefixes should be empty"
