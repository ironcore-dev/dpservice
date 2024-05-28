# When to perform automated benchmarking tests
Automated benchmarking tests are additional functional and performance tests to the existing TAP device-based ones. This test suit relies on a configured environment including hypervisors and started VMs, as well as configured SSH authorized key of the execution machine starting the benchmarking tests.
This benchmarking testing suite is built upon and utilises 1) dpservice-cli to configure running dpservice instances or containers on hypervisors; 2) connectivity and performance testing script under the repository `hack/connectiviy_test`. In the end, running these benchmarking tests is useful for verifying if dpservice works correctly together with actual running VMs for both offloading and non-offloading modes. It also verifies if networking performance meets specified values during dpservice development.

# Examplary command to invoke tests
```
./runtest.py --mode offload --stage cicd --docker-image ghcr.io/ironcore-dev/dpservice:sha-e9b4272 -v

./runtest.py --mode both --stage dev -v
```

# Required hypervisor and VM setup 
To successfully run these automated benchmarking tests, currently, 2 hypervisors and 3 VMs need to be prepared beforehand, especially putting the ssh key of the machine executing the benchmarking tests into the above mentioned hypervisors and VMs. 

## Interface configuration in VMs
To ssh into VMs, QEMU's default networking needs to be activated, and VMs need to be configured to have two interfaces, one using NIC's VF and one connecting to qemu's network bridge. Here is an example of the libvirt default networking configuration file.

```
<network connections='1'>
  <name>default</name>
  <uuid>28910926-4a1c-4f79-8d4c-2f17277727cc</uuid>
  <forward mode='nat'>
    <nat>
      <port start='1024' end='65535'/>
    </nat>
  </forward>
  <bridge name='virbr0' stp='on' delay='0'/>
  <mac address='52:54:00:8c:3c:6f'/>
  <ip address='192.168.122.1' netmask='255.255.255.0'>
    <dhcp>
      <range start='192.168.122.2' end='192.168.122.254'/>
    </dhcp>
  </ip>
</network>
```
## Extra configuration on hypervisors running Gardenlinux
On hypervisors running gardenlinux, it is also necessary to open ports to allow the DHCP service to provide IP addresses to VMs to be able for access. For example, the most convenient way is to  change the default input filter policy to 'accept' by importing the following nft table rules.

```
command: sudo nft -f filter_table.nft
filter_table.nft:
	table inet filter {
			chain input {
					type filter hook input priority filter; policy accept;
					counter packets 1458372 bytes 242766426
					iifname "lo" counter packets 713890 bytes 141369289 accept
					ip daddr 127.0.0.1 counter packets 0 bytes 0 accept
					icmp type echo-request limit rate 5/second burst 5 packets accept
					ip6 saddr ::1 ip6 daddr ::1 counter packets 0 bytes 0 accept
					icmpv6 type { echo-request, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept
					ct state established,related counter packets 627814 bytes 93897896 accept
					tcp dport 22 ct state new counter packets 362 bytes 23104 accept
					rt type 0 counter packets 0 bytes 0 drop
					meta l4proto ipv6-icmp counter packets 0 bytes 0 accept
			}

			chain forward {
					type filter hook forward priority filter; policy accept;
			}

			chain output {
					type filter hook output priority filter; policy accept;
			}
	}
```

In order to add one extra interface dedicated for ssh connection, please modify the VM's libvirt configuration file in the format of XML and add the following section to setup an interface.

```
<interface type='network'>
<mac address='52:54:00:eb:09:93'/>
<source network='default'/>
<model type='virtio'/>
</interface>
```

Additionally, if the used hypervisors are running Gardenlinux, it is needed to remount `/tmp` to allow execute binary files being uploaded to it, due to the strict security policy. Simply execute `sudo mount -o remount,exec /tmp`.

# Configuration file for test environment
The configuration file, `/test/benchmark_test/test_configurations.json` for the test environment provides machine access information and the most of test configurations to the execution script. The following fields need to be double-checked and therefore changed according to the actual environment setup.

1. "host_address", "user_name" and "port" fields in "hypervisors" and "vm" sections. They are needed to remotely access machines which are the foundations for the following operations.

2. "expected_throughput" values need to adapted to the actual environment, as depending on the hardware capability, e.g., CPU speed and cabling specification, the maximum achievable throughput can be different. If these values are too high, tests will always fail.

3. "pci_addr" in "vm" sections needs to match the VF and VM configuration on hypervisors.


# Execution of test script
This test suite is invoked by executing the script `runtest.py` under the repository `/test/benchmark_test`. 

## dpservice-cli
The testing script assumes that dpservice-cli exists under '/tmp' on hypervisors. If you have never run this test suite before, please first compile your local dpservice project by using `meson` and `ninja` commands. Because dpservice-cli is already included in the dpservice repository, the compiled dpservice-cli binary will be transferred to hypervisors automatically.

## Test script's parameters

This script accepts several parameters, which are explained as follows.

1. "--mode". This option specifies which operation mode of dpservice needs to be tested. Select from 'offload', 'non-offload' and 'both'. It must be specified.

2. "--stage". This option specifies which testing stage needs to be used. Choose its value from 'dev' and 'cicd'. The stage of 'dev' is intended for carrying out tests during the development. If this option is set to 'dev', a docker image will be generated from the local repository of dpservice, and this image will be transferred to the hypervisors and executed. For example, a command like `./runtest.py --mode non-offloading --stage deploy -v` will achieve this purpose. 
Alternatively, if this option is set as 'cicd', the above described docker image generating process will not happen. Instead, a docker image specified by the option "--docker-image" will be used on hypervisors. This is a required option.

3. "--docker-image". This option specifies the container image to be deployed to hypervisors. It is optional but required for the 'cicd' stage.

4. "--reboot". This option specifies if a reboot process needs to be performed on VMs. It is needed if test configurations have changed, e.g., private IP addresses of VMs, and VMs need to obtain new configurations. If you want to ensure a fresh start of VMs, this option can also be enabled. It is optional.

5. "--env-config-file" and "--env-config-name". They provide information of the above described `test_configurations.json`. It is possible this file is renamed or located somewhere else. And it is also possible to create several configurations within this file and specify one of them for the tests.

6. "--verbose". Specify if pytest runs in the verbose mode to see all steps and results during test execution.
