#!/bin/bash

# Ensure the script is run as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit
fi

echo "Installing required Python libraries..."
apt update
apt install -y python3-termcolor python3-psutil python3-paramiko python3-jinja2

echo "Checking for Gardenlinux-specific configuration..."

# Check if the system is running Gardenlinux
if grep -qi "gardenlinux" /etc/os-release; then
  echo "Gardenlinux detected. Configuring firewall and remounting /tmp..."

  # Apply the nft rules -- temporarily allow input traffics
  sudo nft add chain inet filter input '{ policy accept; }'

  # Remount /tmp with exec option
  sudo mount -o remount,exec /tmp

  sudo sysctl -w net.ipv4.ip_forward=1

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

# Start net default
sudo virsh net-start default

# Confirm the default network is active
sudo virsh net-list --all

echo "Script execution completed."
