# When to perform automated benchmarking tests
Automated benchmarking tests are additional functional and performance tests to the existing TAP device-based ones. This test suit relies on a configured environment including hypervisors and started VMs, as well as configured SSH authorized key of the execution machine starting the benchmarking tests. In the end, running these benchmarking tests is useful for verifying if dpservice works correctly together with actual running VMs for both offloading and non-offloading modes. It also verifies if networking performance meets specified values during dpservice development.

# Required hypervisor setup
To successfully run these automated benchmarking tests, currently, 2 hypervisors and 3 VMs need to be prepared beforehand.

Please prepare the ssh private/public key pairs and put them under the `.ssh` directory of the server executing the provision script.

The provided script, `hack/connectivity_test/prepare_hypervisor.sh`, can perform extra setups at one time. Please run this script on the involved servers, and the following manual steps can be ignored.

## Prerequisite

1. Ensure the script execution machine can compile dpservice, especiall dpservice-cli within the directory.
2. Install the following python libraries on your executing machine by executing
```
apt install -y python3-termcolor python3-psutil python3-paramiko python3-jinja2
```

## Configuration on hypervisors running Gardenlinux
If the two Servers, that host VMs in tests, run Gardenlinux, and they require extra configurations so that provisioning and benchmarking tests can work.
```
sudo nft add chain inet filter input '{ policy accept; }'
```


## Enable QEMU's default networking
To ssh into VMs, QEMU's default networking needs to be activated and configured to support IP address assignment via DHCP. Enter the libvirt's default network editing mode by running `sudo virsh net-edit default`, copy the configureation and restart libvirt service by running `sudo systemctl restart libvirtd`.

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

The above steps are needed on hypervsiors to support automated provision of VMs and benchmark testing.

# Provision VMs
The script, `provision.py`, is able to create needed VMs according to the test_configuration.json file. This configuration file is copied into a newly created directory `/test/benchmark_test/provision_templates` and updated with VM's accessing IP address during the provision process. Right now, it provisions three VMs to meet the setup requirement of running benchmark tests.

## Prepare Gardenlinux image (.raw)
This step is manual, as the compilation of the kernel is time consuming and once it is done, it can be reused for quite some time. Two steps are needed to prepare the gardenlinux VM image.

1. Clone [Gardenlinux](https://github.com/gardenlinux/gardenlinux) source code using git.
2. Inside the cloned repo, run `./build kvm-amd64`. The built image can be found under `./build/kvm-amd64-today-local.raw`, and remember the absolute path of this image file.

## Configuration file for test environment
The configuration file, `/test/benchmark_test/config_templates/test_configurations.json` for the test environment provides machine access information and the most of test configurations to the execution script. The following fields need to be double-checked and therefore changed according to the actual environment setup.

1. "host_address", "user_name" and "port" fields in "hypervisors" sections. They are needed to remotely access machines which are the foundations for the following operations.

2. "expected_throughput" values need to adapted to the actual environment, as depending on the hardware capability, e.g., CPU speed and cabling specification, the maximum achievable throughput can be different. If these values are too high, tests will always fail.

3. "pci_addr" in "vm" sections needs to match the VF and VM configuration on hypervisors.

4. "machine_name" field is NOT expected to be changed.

## Ignition file
To have a complete ignition file template, `./benchmark_test/config_templates/provision_tmpl.ign`, please contact the maintainers for a proper hashed password to fill in.


## Run the provision script
The most commonly used commands to run the provision script are as follows.
1. `./provision.py --disk-template <path to the compiled gardenlinux image file>`. For example, , e.g., `./provision.py --disk-template /home/gardenlinux/.build/kvm-amd64-today-local.raw`. It is expected that the defined VMs are provisioned on two hypervsiors, and their access IPs are updated in the `test_configurations.json` file.

2. `./provision.py --clean-up`. It is expected that the provisioned VMs are destroyed and undefined.

It is possible to login into the provisioned VMs with the user name `root` and password `test123`, using the libvirt's console.

# Execution of test script
This test suite is invoked by executing the script `runtest.py` under the repository `/test/benchmark_test`. In oder to run dpservice either natively or via container, please make sure that a valid dpservice.conf file is created under `/run/dpservice`.

## dpservice-cli
The testing script assumes that dpservice-cli exists under '/tmp' on hypervisors. If you have never run this test suite before, please first compile your local dpservice project by using `meson` and `ninja` commands. Because dpservice-cli is already included in the dpservice repository, the compiled dpservice-cli binary will be transferred to hypervisors automatically.

## Test script's parameters

This script accepts several parameters, which are explained as follows.
1. `--mode`. This option specifies which operation mode of dpservice needs to be tested. Select from 'offload', 'non-offload' and 'both'. It must be specified.

2. `--stage`. This option specifies which testing stage needs to be used. Choose its value from 'dev' and 'cicd'. The stage of 'dev' is intended for carrying out tests during the development. If this option is set to 'dev', a docker image will be generated from the local repository of dpservice, and this image will be transferred to the hypervisors and executed. For example, a command like `./runtest.py --mode non-offloading --stage dev -v` will achieve this purpose.
Alternatively, if this option is set as 'cicd', the above described docker image generating process will not happen. Instead, a docker image specified by the option "--docker-image" will be used on hypervisors. This is a required option.

3. `--docker-image`. This option specifies the container image to be deployed to hypervisors. It is optional but required for the 'cicd' stage.

4. `--reboot`. This option specifies if a reboot process needs to be performed on VMs. It is needed if test configurations have changed, e.g., private IP addresses of VMs, and VMs need to obtain new configurations. If you want to ensure a fresh start of VMs, this option can also be enabled. It is optional, but it is recommended to set this flag so that each machine is able to receive newest interface configurations.

5. `--env-config-file` and `--env-config-name`. They provide information of the above described `test_configurations.json`. It is possible this file is renamed or located somewhere else. And it is also possible to create several configurations within this file and specify one of them for the tests.

6. `--verbose`. Specify if pytest runs in the verbose mode to see all steps and results during test execution.

# Examplary command to invoke tests
```
./run_benchmarktest.py --mode offload --stage cicd --docker-image ghcr.io/ironcore-dev/dpservice:sha-e9b4272 --reboot -v

./run_benchmarktest.py --mode both --stage dev --reboot -v
```
