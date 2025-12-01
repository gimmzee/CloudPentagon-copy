terraform {
  required_version = ">= 1.0"
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

# Variables
variable "project_name" {
  description = "Project name for resource naming"
  type        = string
  default     = "cloudpentagon"
}

variable "environment" {
  description = "Environment for resource naming"
  type        = string
  default     = "dev"
}

variable "location" {
  description = "Azure region"
  type        = string
  default     = "koreacentral"
}

# Resource Group
resource "azurerm_resource_group" "main" {
  name     = "${var.project_name}-${var.environment}-rg"
  location = var.location

  tags = {
    Environment = var.environment
    Project     = var.project_name
  }
}

# ========================================
# VNet1 - Production Environment
# ========================================

resource "azurerm_virtual_network" "vnet1" {
  name                = "VNet1-Korea-Production"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  address_space       = ["10.2.0.0/16"]

  tags = {
    Name = "VNet1-Korea-Production"
  }
}

# ========================================
# Subnets for VNet1
# ========================================

# Public Subnet for Application Gateway
resource "azurerm_subnet" "vnet1_public" {
  name                 = "VNet1-Public-Subnet"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.vnet1.name
  address_prefixes     = ["10.2.1.0/24"]
}

# Frontend Container Subnet
resource "azurerm_subnet" "vnet1_frontend" {
  name                 = "VNet1-Frontend-Subnet"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.vnet1.name
  address_prefixes     = ["10.2.11.0/24"]

  delegation {
    name = "container-delegation"
    service_delegation {
      name    = "Microsoft.ContainerInstance/containerGroups"
      actions = ["Microsoft.Network/virtualNetworks/subnets/action"]
    }
  }
}

# Private Subnet for Internal LB 
resource "azurerm_subnet" "lb_subnet" {
  name                 = "VNet1-lb-subnet"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.vnet1.name
  address_prefixes = ["10.2.21.0/24"]

  private_link_service_network_policies_enabled = false
}


# Backend Container Subnet
resource "azurerm_subnet" "vnet1_backend" {
  name                 = "VNet1-Backend-Subnet"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.vnet1.name
  address_prefixes     = ["10.2.31.0/24"]

  delegation {
    name = "container-delegation"
    service_delegation {
      name    = "Microsoft.ContainerInstance/containerGroups"
      actions = ["Microsoft.Network/virtualNetworks/subnets/action"]
    }
  }
}


# Database Subnet
resource "azurerm_subnet" "vnet1_db" {
  name                 = "VNet1-DB-Subnet"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.vnet1.name
  address_prefixes     = ["10.2.41.0/24"]

  delegation {
    name = "mysql-delegation"
    service_delegation {
      name = "Microsoft.DBforMySQL/flexibleServers"
      actions = [
        "Microsoft.Network/virtualNetworks/subnets/join/action"
      ]
    }
  }
}


# ========================================
# Network Security Groups
# ========================================

# Public NSG (Application Gateway)
resource "azurerm_network_security_group" "public_nsg" {
  name                = "public-nsg"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  security_rule {
    name                       = "Allow-HTTP"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "80"
    source_address_prefix      = "Internet"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "Allow-HTTPS"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "Internet"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "Allow-AppGateway-Ports"
    priority                   = 120
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "65200-65535"
    source_address_prefix      = "GatewayManager"
    destination_address_prefix = "*"
  }

  tags = {
    Name = "Public-NSG"
  }
}

# Frontend NSG
resource "azurerm_network_security_group" "frontend_nsg" {
  name                = "frontend-nsg"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  security_rule {
    name                       = "Allow-HTTP-from-AppGateway"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "80"
    source_address_prefix      = "10.2.1.0/24"
    destination_address_prefix = "*"
  }

  # ILB Health Probe 허용
  security_rule {
    name                       = "Allow-ILB-HealthProbe"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "AzureLoadBalancer"
    destination_address_prefix = "*"
  }

  # Frontend에서 Backend(ILB 경유)로 Outbound
  security_rule {
    name                       = "Allow-to-Backend-via-ILB"
    priority                   = 100
    direction                  = "Outbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "80"
    source_address_prefix      = "*"
    destination_address_prefix = "10.1.11.0/24"  # ILB 자신도 이 서브넷에 있음
  }

  security_rule {
    name                       = "Allow-Internet-Outbound"
    priority                   = 110
    direction                  = "Outbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "Internet"
  }
  tags = {
    Name = "Frontend-NSG"
  }
}

# Backend NSG
resource "azurerm_network_security_group" "backend_nsg" {
  name                = "backend-nsg"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  security_rule {
    name                       = "Allow-HTTP-from-Frontend"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "8000"
    source_address_prefix      = "10.2.11.0/24"
    destination_address_prefix = "*"
  }

  tags = {
    Name = "Backend-NSG"
  }
}

# Database NSG
resource "azurerm_network_security_group" "db_nsg" {
  name                = "db-nsg"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  security_rule {
    name                       = "Allow-MySQL-from-Backend"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3306"
    source_address_prefix      = "10.2.21.0/24"
    destination_address_prefix = "*"
  }

  tags = {
    Name = "DB-NSG"
  }
}

# NSG Associations
resource "azurerm_subnet_network_security_group_association" "public_nsg_assoc" {
  subnet_id                 = azurerm_subnet.vnet1_public.id
  network_security_group_id = azurerm_network_security_group.public_nsg.id
}

resource "azurerm_subnet_network_security_group_association" "frontend_nsg_assoc" {
  subnet_id                 = azurerm_subnet.vnet1_frontend.id
  network_security_group_id = azurerm_network_security_group.frontend_nsg.id
}

resource "azurerm_subnet_network_security_group_association" "backend_nsg_assoc" {
  subnet_id                 = azurerm_subnet.vnet1_backend.id
  network_security_group_id = azurerm_network_security_group.backend_nsg.id
}

resource "azurerm_subnet_network_security_group_association" "db_nsg_assoc" {
  subnet_id                 = azurerm_subnet.vnet1_db.id
  network_security_group_id = azurerm_network_security_group.db_nsg.id
}


# ========================================
# Log Analytics Workspace
# ========================================

resource "azurerm_log_analytics_workspace" "logs" {
  name                = "${var.project_name}-${var.environment}-logs"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  sku                 = "PerGB2018"
  retention_in_days   = 30

  tags = {
    Name = "Log-Analytics"
  }
}

# ========================================
# Public IP for Application Gateway
# ========================================

resource "azurerm_public_ip" "appgw_pip" {
  name                = "appgw-pip"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  allocation_method   = "Static"
  sku                 = "Standard" #Standard SKU는 기본적으로 zone-redundant
  zones = ["1","2"]

  tags = {
    Name = "AppGateway-PublicIP"
  }
}

# ========================================
# Application Gateway (Public ALB equivalent)
# ========================================

locals {
  backend_address_pool_name      = "frontend-backend-pool"
  frontend_port_name             = "frontend-port"
  frontend_ip_configuration_name = "frontend-ip"
  http_setting_name              = "frontend-http-setting"
  listener_name                  = "frontend-listener"
  request_routing_rule_name      = "frontend-rule"
}

resource "azurerm_application_gateway" "appgw" {
  name                = "public-appgw"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  zones               = ["1", "2"]  # Zone Redundant

  sku {
    name     = "Standard_v2"
    tier     = "Standard_v2"
    capacity = 2
  }

  ssl_policy {
    policy_type = "Predefined"
    policy_name = "AppGwSslPolicy20220101"   # ← 최신 권장 정책(또는 AppGwSslPolicy20220101S)
  }

  gateway_ip_configuration {
    name      = "appgw-ip-config"
    subnet_id = azurerm_subnet.lb_subnet.id
  }

  frontend_port {
    name = local.frontend_port_name
    port = 80
  }

  frontend_ip_configuration {
    name                 = local.frontend_ip_configuration_name
    public_ip_address_id = azurerm_public_ip.appgw_pip.id
  }

  backend_address_pool {
    name = local.backend_address_pool_name
  }

  backend_http_settings {
    name                  = local.http_setting_name
    cookie_based_affinity = "Disabled"
    port                  = 80
    protocol              = "Http"
    request_timeout       = 30
    probe_name            = "frontend-probe"
  }

  probe {
    name                = "frontend-probe"
    protocol            = "Http"
    path                = "/health"
    interval            = 30
    timeout             = 30
    unhealthy_threshold = 3
    host                = "backend.internal.local"
  }

  http_listener {
    name                           = local.listener_name
    frontend_ip_configuration_name = local.frontend_ip_configuration_name
    frontend_port_name             = local.frontend_port_name
    protocol                       = "Http"
  }

  request_routing_rule {
    name                       = local.request_routing_rule_name
    rule_type                  = "Basic"
    http_listener_name         = local.listener_name
    backend_address_pool_name  = local.backend_address_pool_name
    backend_http_settings_name = local.http_setting_name
    priority                   = 100
  }

  tags = {
    Name = "Public-AppGateway"
  }
}

#backend_address_pool에 직접 IP를 설정
# ========================================
# Container Instances - Frontend (Multi-Zone)
# ========================================

# Frontend Container - Zone 1
resource "azurerm_container_group" "frontend_zone1" {
  name                = "frontend-zone1"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  os_type             = "Linux"
  subnet_ids          = [azurerm_subnet.vnet1_frontend.id]
  zones               = ["3"]  # Availability Zone 3
  ip_address_type = "Private"

  image_registry_credential {
    server   = data.azurerm_container_registry.frontendapp1.login_server
    username = var.acr_sp_username
    password = var.acr_sp_password
  }


  container {
    name   = "frontend"
    image  = "${data.azurerm_container_registry.frontendapp1.login_server}/frontendapp1:latest"
    cpu    = "0.5"
    memory = "1.0"

    ports {
      port     = 80
      protocol = "TCP"
    }
  }

  diagnostics {
    log_analytics {
      workspace_id  = azurerm_log_analytics_workspace.logs.workspace_id
      workspace_key = azurerm_log_analytics_workspace.logs.primary_shared_key
    }
  }

  tags = {
    Name = "Frontend-Zone1"
    Tier = "Application"
    Zone = "1"
  }
}

# Frontend Container - Zone 2
resource "azurerm_container_group" "frontend_zone2" {
  name                = "frontend-zone2"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  os_type             = "Linux"
  subnet_ids          = [azurerm_subnet.vnet1_frontend.id]
  zones               = ["2"]  # Availability Zone 2
  ip_address_type = "Private"

  image_registry_credential {
    server   = data.azurerm_container_registry.frontendapp1.login_server
    username = var.acr_sp_username
    password = var.acr_sp_password
  }

  container {
    name   = "frontend"
    image  = "${data.azurerm_container_registry.frontendapp1.login_server}/frontendapp1:latest"
    cpu    = "0.5"
    memory = "1.0"

    ports {
      port     = 80
      protocol = "TCP"
    }
  }

  diagnostics {
    log_analytics {
      workspace_id  = azurerm_log_analytics_workspace.logs.workspace_id
      workspace_key = azurerm_log_analytics_workspace.logs.primary_shared_key
    }
  }

  tags = {
    Name = "Frontend-Zone2"
    Tier = "Application"
    Zone = "2"
  }
}
# ========================================
# Internal Load Balancer for Backend 
# ========================================

resource "azurerm_lb" "internal_lb" {
  name                = "internal-lb"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  sku                 = "Standard" #Standard SKU는 기본적으로 zone-redundant

  frontend_ip_configuration {
    name                          = "internal-frontend"
    subnet_id                     = azurerm_subnet.vnet1_frontend.id
    private_ip_address_allocation = "Dynamic"
  }

  tags = {
    Name = "Internal-LoadBalancer"
  }
}

resource "azurerm_lb_backend_address_pool" "backend_pool" {
  loadbalancer_id = azurerm_lb.internal_lb.id
  name            = "backend-pool"
}

resource "azurerm_lb_probe" "backend_probe" {
  loadbalancer_id = azurerm_lb.internal_lb.id
  name            = "backend-probe"
  protocol        = "Http"
  port            = 8000
  request_path    = "/health"
}

resource "azurerm_lb_rule" "backend_rule" {
  loadbalancer_id                = azurerm_lb.internal_lb.id
  name                           = "backend-rule"
  protocol                       = "Tcp"
  frontend_port                  = 80
  backend_port                   = 8000
  frontend_ip_configuration_name = "internal-frontend"
  backend_address_pool_ids       = [azurerm_lb_backend_address_pool.backend_pool.id]
  probe_id                       = azurerm_lb_probe.backend_probe.id
}

# ========================================
# Backend Pool Addresses
# ========================================

# Backend Zone 1을 Load Balancer Pool에 추가
resource "azurerm_lb_backend_address_pool_address" "backend_zone1" {
  name                    = "backend-zone1"
  backend_address_pool_id = azurerm_lb_backend_address_pool.backend_pool.id
  virtual_network_id      = azurerm_virtual_network.vnet1.id
  ip_address              = azurerm_container_group.backend_zone1.ip_address
}

# Backend Zone 2를 Load Balancer Pool에 추가
resource "azurerm_lb_backend_address_pool_address" "backend_zone2" {
  name                    = "backend-zone2"
  backend_address_pool_id = azurerm_lb_backend_address_pool.backend_pool.id
  virtual_network_id      = azurerm_virtual_network.vnet1.id
  ip_address              = azurerm_container_group.backend_zone2.ip_address
}

# ========================================
# Container Instances - Backend
# ========================================

# Backend Container - Zone 1
resource "azurerm_container_group" "backend_zone1" {
  name                = "backend-zone1"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  os_type             = "Linux"
  subnet_ids          = [azurerm_subnet.vnet1_backend.id]
  zones               = ["1"]  # Availability Zone 1

  image_registry_credential {
    server   = data.azurerm_container_registry.backendapp1.login_server
    username = var.acr_sp_username
    password = var.acr_sp_password
  }

  container {
    name   = "backend"
    image  = "${data.azurerm_container_registry.backendapp1.login_server}/backendapp1:latest"
    cpu    = "1.0"
    memory = "2.0"

    ports {
      port     = 8000
      protocol = "TCP"
    }

    #Azure Key Manager(Key Vault) 방식 전환하기
    environment_variables = {
      CLOUD_API_KEY    = "222768776744816"
      CLOUD_API_SECRET = "1kj1qRyaxurxfH3vM6I3TJImlgQ"
      CLOUD_NAME       = "dqqhihcfa"
      DB_USERNAME      = "sqladmin"
    }

    secure_environment_variables = {
      DB_PASSWORD = "P@ssw0rd1234!ComplexPassword"
      DB_URL      = "jdbc:mysql://${azurerm_mysql_flexible_server.dr_mysql.fqdn}:3306/sqlDB?useSSL=true&requireSSL=true&serverTimezone=UTC"
    }
  }

  diagnostics {
    log_analytics {
      workspace_id  = azurerm_log_analytics_workspace.logs.workspace_id
      workspace_key = azurerm_log_analytics_workspace.logs.primary_shared_key
    }
  }

  tags = {
    Name = "Backend-Zone1"
    Tier = "Application"
    Zone = "1"
  }
}

# Backend Container - Zone 2
resource "azurerm_container_group" "backend_zone2" {
  name                = "backend-zone2"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  os_type             = "Linux"
  subnet_ids          = [azurerm_subnet.vnet1_backend.id]
  zones               = ["2"]  # Availability Zone 2

  image_registry_credential {
    server   = data.azurerm_container_registry.backendapp1.login_server
    username = var.acr_sp_username
    password = var.acr_sp_password
  }

  container {
    name   = "backend"
    image  = "${data.azurerm_container_registry.backendapp1.login_server}/backendapp1:latest"
    cpu    = "1.0"
    memory = "2.0"

    ports {
      port     = 8000
      protocol = "TCP"
    }

    environment_variables = {
      CLOUD_API_KEY    = "222768776744816"
      CLOUD_API_SECRET = "1kj1qRyaxurxfH3vM6I3TJImlgQ"
      CLOUD_NAME       = "dqqhihcfa"
      DB_USERNAME      = "sqladmin"
    }

    secure_environment_variables = {
      DB_PASSWORD = "Soldeskqwe123!"
      DB_URL      = "jdbc:mysql://${azurerm_mysql_flexible_server.dr_mysql.fqdn}:3306/sqlDB?useSSL=true&requireSSL=true&serverTimezone=UTC"
    }
  }

  diagnostics {
    log_analytics {
      workspace_id  = azurerm_log_analytics_workspace.logs.workspace_id
      workspace_key = azurerm_log_analytics_workspace.logs.primary_shared_key
    }
  }

  tags = {
    Name = "Backend-Zone2"
    Tier = "Application"
    Zone = "2"
  }
}

# MySQL Flexible Server 추가
resource "azurerm_mysql_flexible_server" "dr_mysql" {
  name                   = "dr-mysql-server-${random_string.unique.result}"
  resource_group_name    = azurerm_resource_group.main.name
  location               = azurerm_resource_group.main.location
  administrator_login    = "mysqladmin"
  administrator_password = "Soldeskqwe123!"
  
  sku_name = "B_Standard_B2s"
  version    = "8.0.21"
  # zone = "3" #Zone 지정 안 하면 Azure가 가용한 zone을 자동 선택

  storage {
    size_gb = 20
  }

  backup_retention_days        = 7
  geo_redundant_backup_enabled = false

  delegated_subnet_id = azurerm_subnet.vnet1_db.id

  # private_dns_zone_id = azurerm_private_dns_zone.mysql_dns.id
  # depends_on = [azurerm_private_dns_zone_virtual_network_link.mysql_dns_link]
}

#서버 이름 중복 방지
resource "random_string" "unique" {
  length  = 6
  special = false
  upper   = false
}

# # MySQL Private DNS Zone
# resource "azurerm_private_dns_zone" "mysql_dns" {
#   name                = "privatelink.mysql.database.azure.com"
#   resource_group_name = azurerm_resource_group.main.name
# }

# resource "azurerm_private_dns_zone_virtual_network_link" "mysql_dns_link" {
#   name                  = "mysql-dns-link"
#   resource_group_name   = azurerm_resource_group.main.name
#   private_dns_zone_name = azurerm_private_dns_zone.mysql_dns.name
#   virtual_network_id    = azurerm_virtual_network.vnet1.id
# }

# MySQL Database
resource "azurerm_mysql_flexible_database" "sqldb" {
  name                = "sqlDB"
  resource_group_name = azurerm_resource_group.main.name
  server_name         = azurerm_mysql_flexible_server.dr_mysql.name
  charset             = "utf8mb4"
  collation           = "utf8mb4_unicode_ci"
}


# ========================================
# ACR Data Source
# ========================================
# Frontend ACR
data "azurerm_container_registry" "frontendapp1" {
  name                = var.acr_name_frontend
  resource_group_name = var.resource_group_frontend
}

# Backend ACR
data "azurerm_container_registry" "backendapp1" {
  name                = var.acr_name_backend
  resource_group_name = var.resource_group_backend
}

variable "acr_sp_username" {
  type      = string
  sensitive = true
}

variable "acr_sp_password" {
  type      = string
  sensitive = true
}

variable "acr_name_frontend" {
  type = string
}

variable "acr_name_backend" {
  type = string
}

variable "resource_group_frontend" {
  type = string
}

variable "resource_group_backend" {
  type = string
}




# ========================================
# Outputs
# ========================================

output "frontend_container_zone1_ip" {
  value = azurerm_container_group.frontend_zone1.ip_address
}

output "frontend_container_zone2_ip" {
  value = azurerm_container_group.frontend_zone2.ip_address
}

output "backend_container_zone1_ip" {
  value = azurerm_container_group.backend_zone1.ip_address
}

output "backend_container_zone2_ip" {
  value = azurerm_container_group.backend_zone2.ip_address
}

output "mysql_fqdn" {
  value     = azurerm_mysql_flexible_server.dr_mysql.fqdn
  sensitive = true
}

output "application_gateway_public_ip" {
  value = azurerm_public_ip.appgw_pip.ip_address
}