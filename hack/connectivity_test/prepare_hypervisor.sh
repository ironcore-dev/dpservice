#!/bin/bash

# Ensure the script is run as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit
fi

echo "Installing required Python libraries..."
apt update
apt install -y python3-termcolor python3-psutil python3-paramiko

echo "Checking for Gardenlinux-specific configuration..."

# Check if the system is running Gardenlinux
if grep -qi "gardenlinux" /etc/os-release; then
  echo "Gardenlinux detected. Configuring firewall and remounting /tmp..."

  # Open ports for DHCP service by importing nft table rules
  nft_filter_rules="/tmp/filter_table.nft"

  # Create nft table rules file
  cat <<EOF > $nft_filter_rules
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
EOF

  # Apply the nft rules
  sudo nft flush table inet filter
  sudo nft -f $nft_filter_rules

  # Remount /tmp with exec option
  sudo mount -o remount,exec /tmp

  echo "Gardenlinux-specific configuration completed."
else
  echo "Non-Gardenlinux system detected. Skipping Gardenlinux-specific configuration."
fi

# Define the XML configuration for the default network
NETWORK_XML=$(cat <<EOF
<network connections='1'>
  <name>default</name>
  <uuid>$(uuidgen)</uuid>
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
EOF
)

# Backup the existing network configuration
sudo cp /etc/libvirt/qemu/networks/default.xml /etc/libvirt/qemu/networks/default.xml.backup

# Apply the new network configuration
echo "$NETWORK_XML" | sudo tee /etc/libvirt/qemu/networks/default.xml > /dev/null

# Restart the libvirt service
sudo systemctl restart libvirtd

# Confirm the default network is active
sudo virsh net-list --all

echo "Script execution completed."