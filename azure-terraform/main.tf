# Configure the Azure provider
terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }
}

provider "azurerm" {
  features {}
}

# Resource Group to keep all project resources together
resource "azurerm_resource_group" "anon_rg" {
  name     = "rg-anon-network"
  location = "West Europe"
}

# Networking: Core VNet and Subnet setup
resource "azurerm_virtual_network" "anon_vnet" {
  name                = "vnet-anon"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.anon_rg.location
  resource_group_name = azurerm_resource_group.anon_rg.name
}

resource "azurerm_subnet" "anon_subnet" {
  name                 = "subnet-anon"
  resource_group_name  = azurerm_resource_group.anon_rg.name
  virtual_network_name = azurerm_virtual_network.anon_vnet.name
  address_prefixes     = ["10.0.1.0/24"]
}

# Static Public IP for the P2P node
resource "azurerm_public_ip" "anon_ip" {
  name                = "pip-anon-node"
  location            = azurerm_resource_group.anon_rg.location
  resource_group_name = azurerm_resource_group.anon_rg.name
  allocation_method   = "Static" # Static IP is required for stable P2P connections
}

# Network Security Group (Firewall rules)
resource "azurerm_network_security_group" "anon_nsg" {
  name                = "nsg-anon"
  location            = azurerm_resource_group.anon_rg.location
  resource_group_name = azurerm_resource_group.anon_rg.name

  # Allow incoming SSH traffic
  security_rule {
    name                       = "SSH"
    priority                   = 1001
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  # Open port for P2P TCP traffic
  security_rule {
    name                       = "Anon-TCP"
    priority                   = 1002
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "7656"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  # Open port for P2P UDP traffic
  security_rule {
    name                       = "Anon-UDP"
    priority                   = 1003
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Udp"
    source_port_range          = "*"
    destination_port_range     = "7656"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

# Network Interface (NIC) for the VM
resource "azurerm_network_interface" "anon_nic" {
  name                = "nic-anon"
  location            = azurerm_network_interface.anon_nic.location # Fixed for consistency
  resource_group_name = azurerm_resource_group.anon_rg.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.anon_subnet.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.anon_ip.id
  }
}

# Bind NSG to the network interface
resource "azurerm_network_interface_security_group_association" "anon_nic_nsg" {
  network_interface_id      = azurerm_network_interface.anon_nic.id
  network_security_group_id = azurerm_network_security_group.anon_nsg.id
}

# Relay Node VM with Cloud-init provisioning
resource "azurerm_linux_virtual_machine" "anon_vm" {
  name                  = "vm-anon-relay"
  resource_group_name   = azurerm_resource_group.anon_rg.name
  location              = azurerm_resource_group.anon_rg.location
  size                  = "Standard_B1s"
  admin_username        = "azureuser"
  network_interface_ids = [azurerm_network_interface.anon_nic.id]

  admin_ssh_key {
    username   = "azureuser"
    public_key = file("~/.ssh/id_rsa.pub") # Read local public key
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts"
    version   = "latest"
  }

  # Cloud-init script to configure the OS on first boot
  custom_data = base64encode(<<-EOF
    #!/bin/bash
    REMOTE_DIR="/opt/anon-router"
    mkdir -p $REMOTE_DIR
    
    # Generate router configuration file
    cat > $REMOTE_DIR/config.json << 'CFGEOF'
    {
        "listen_address": "0.0.0.0",
        "listen_port": 7656,
        "is_floodfill": true,
        "log_level": "INFO"
    }
    CFGEOF

    # Create systemd service unit for the router
    cat > /etc/systemd/system/anon-router.service << 'SVCEOF'
    [Unit]
    Description=Anonymous P2P Network Router
    After=network-online.target

    [Service]
    Type=simple
    WorkingDirectory=$REMOTE_DIR
    ExecStart=$REMOTE_DIR/anon-router -config $REMOTE_DIR/config.json
    Restart=always
    RestartSec=5
    LimitNOFILE=65535

    [Install]
    WantedBy=multi-user.target
    SVCEOF

    systemctl daemon-reload
    systemctl enable anon-router
  EOF
  )
}

# Output the public IP to connect easily
output "public_ip" {
  value = azurerm_public_ip.anon_ip.ip_address
}