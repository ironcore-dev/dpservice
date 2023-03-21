from helpers import *

def test_grpc_addmachine_wrong_ip(prepare_ifaces, grpc_client):
    # Try to add using an existing vm identifier
    grpc_client.assert_output(f"--addmachine {vm2_name} --vni {vni} --ipv4 1926.168.3.4 --ipv6 {vf1_ipv6}",
        "Received an error 100")

def test_grpc_addmachine_wrong_ip(prepare_ifaces, grpc_client):
    # Try to add using an existing vm identifier
    grpc_client.assert_output(f"--addmachine {vm2_name} --vni {vni} --ipv4 182:3.4.8 --ipv6 {vf1_ipv6}",
        "wrong primary ip: 182:3.4.8")
