terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
  }
}

provider "azurerm" {
  features {}
  subscription_id = var.subscription_id
}

# ------------------------------
# 1. Resource Group
# ------------------------------
resource "azurerm_resource_group" "dr_rg" {
  name     = "dr-azure-rg"
  location = var.location
}

# ------------------------------
# 2. Virtual Network & Subnet
# ------------------------------
resource "azurerm_virtual_network" "dr_vnet" {
  name                = "dr-vnet"
  address_space       = ["10.10.0.0/16"]
  location            = var.location
  resource_group_name = azurerm_resource_group.dr_rg.name
}

resource "azurerm_subnet" "dr_subnet" {
  name                 = "dr-subnet"
  resource_group_name  = azurerm_resource_group.dr_rg.name
  virtual_network_name = azurerm_virtual_network.dr_vnet.name
  address_prefixes     = ["10.10.1.0/24"]
}

# ------------------------------
# 3. Network Security Group
# ------------------------------
resource "azurerm_network_security_group" "dr_nsg" {
  name                = "dr-web-nsg"
  location            = var.location
  resource_group_name = azurerm_resource_group.dr_rg.name

  security_rule {
    name                       = "allow-http"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "80"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "allow-ssh"
    priority                   = 101
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

# NSG와 Subnet 연결
resource "azurerm_subnet_network_security_group_association" "dr_nsg_assoc" {
  subnet_id                 = azurerm_subnet.dr_subnet.id
  network_security_group_id = azurerm_network_security_group.dr_nsg.id
}

# ------------------------------
# 4. Public IP (Standard SKU)
# ------------------------------
resource "azurerm_public_ip" "dr_public_ip" {
  name                = "dr-public-ip"
  location            = var.location
  resource_group_name = azurerm_resource_group.dr_rg.name
  sku                 = "Standard"
  allocation_method   = "Static"
  zones               = ["1"]  # 가용성 영역 (선택사항)
}

# ------------------------------
# 5. Network Interface
# ------------------------------
resource "azurerm_network_interface" "dr_nic" {
  name                = "dr-nic"
  location            = var.location
  resource_group_name = azurerm_resource_group.dr_rg.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.dr_subnet.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.dr_public_ip.id
  }
}

# ------------------------------
# 6. Linux VM (Free Tier B1s)
# ------------------------------
resource "azurerm_linux_virtual_machine" "dr_vm" {
  name                = "dr-web-vm"
  location            = var.location
  resource_group_name = azurerm_resource_group.dr_rg.name
  size                = var.vm_size
  admin_username      = var.admin_username

  network_interface_ids = [
    azurerm_network_interface.dr_nic.id
  ]

  admin_ssh_key {
    username   = var.admin_username
    public_key = file(var.ssh_public_key_path)
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
    disk_size_gb         = 30  # Free Tier: 최대 64GB, 30GB로 최적화
  }

  # Ubuntu 22.04 LTS
  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts-gen2"
    version   = "latest"
  }

  # 부팅 진단 비활성화 (비용 절감)
  boot_diagnostics {
    storage_account_uri = null
  }

  # 선택사항: cloud-init으로 웹서버 자동 설치
  custom_data = base64encode(<<-EOF
    #!/bin/bash
    sudo apt-get update
    sudo apt-get install -y nginx
    echo "<h1>DR Server - Azure</h1>" | sudo tee /var/www/html/index.html
    sudo systemctl start nginx
    sudo systemctl enable nginx
  EOF
  )
}

# ------------------------------
# Variables
# ------------------------------
variable "subscription_id" {
  description = "Azure Subscription ID"
  type        = string
  # 실행 시: export TF_VAR_subscription_id="7adc47d6-5071-4675-9c57-70443589cb62"
}

variable "location" {
  description = "Azure region for DR"
  type        = string
  default     = "koreacentral"  # 소문자, 공백 없이
}

variable "vm_size" {
  description = "VM Size (Free Tier: B1s)"
  type        = string
  default     = "Standard_B1s"  # Free Tier: 750시간/월 무료
  # 참고: B1ls는 더 저렴하지만 성능이 매우 낮음
}

variable "admin_username" {
  description = "Admin username for VM"
  type        = string
  default     = "azureuser"
}

variable "ssh_public_key_path" {
  description = "Path to SSH public key"
  type        = string
  default     = "~/.ssh/id_rsa.pub"
  # Windows: "C:/Users/soldesk/.ssh/id_rsa.pub"
  # Linux/Mac: "~/.ssh/id_rsa.pub"
}

# ------------------------------
# Outputs
# ------------------------------
output "resource_group_name" {
  description = "Resource Group name"
  value       = azurerm_resource_group.dr_rg.name
}

output "public_ip" {
  description = "Public IP address (Dynamic - allocated after VM starts)"
  value       = azurerm_public_ip.dr_public_ip.ip_address
}

output "vm_name" {
  description = "VM name"
  value       = azurerm_linux_virtual_machine.dr_vm.name
}

output "vm_id" {
  description = "VM resource ID"
  value       = azurerm_linux_virtual_machine.dr_vm.id
}

output "ssh_command" {
  description = "SSH connection command"
  value       = "ssh ${var.admin_username}@${azurerm_public_ip.dr_public_ip.ip_address}"
}

output "web_url" {
  description = "Web server URL"
  value       = "http://${azurerm_public_ip.dr_public_ip.ip_address}"
}