# One VPC with one public subnet in one availability zone, and the
# machines the benchmark plans need: a control-plane host, agent hosts,
# relays, and a middle box that plays both the relay and the
# WireGuard-terminating gateway against the same hosts.

locals {
  agent_names = [for i in range(var.agent_count) : "h${i + 1}"]
  relay_names = [for i in range(var.relay_count) : "r${i + 1}"]

  # Every machine, by the name sdn-lab and the control plane know it by.
  machines = merge(
    { cp = { role = "cp", type = var.cp_instance_type } },
    { mid = { role = "middle", type = var.middle_instance_type } },
    { for n in local.agent_names : n => { role = "agent", type = var.agent_instance_type } },
    { for n in local.relay_names : n => { role = "relay", type = var.relay_instance_type } },
  )

  availability_zone = var.availability_zone != "" ? var.availability_zone : data.aws_availability_zones.available.names[0]
  key_name          = var.ssh_public_key != "" ? aws_key_pair.operator[0].key_name : var.key_name
}

data "aws_availability_zones" "available" {
  state = "available"
}

# Ubuntu 24.04, the substrate SPEC.md's c6i.xlarge figures came from.
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
}

resource "aws_vpc" "fleet" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = var.name }
}

resource "aws_internet_gateway" "fleet" {
  vpc_id = aws_vpc.fleet.id

  tags = { Name = var.name }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.fleet.id
  cidr_block              = var.subnet_cidr
  availability_zone       = local.availability_zone
  map_public_ip_on_launch = true

  tags = { Name = "${var.name}-public" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.fleet.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.fleet.id
  }

  tags = { Name = "${var.name}-public" }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# SSH from the operator, and everything between members of the fleet:
# the control plane's API, relay ports, WireGuard, telemetry and the
# benchmark traffic itself.
resource "aws_security_group" "fleet" {
  name        = var.name
  description = "sdn.sh benchmark fleet"
  vpc_id      = aws_vpc.fleet.id

  tags = { Name = var.name }
}

resource "aws_vpc_security_group_ingress_rule" "ssh" {
  security_group_id = aws_security_group.fleet.id
  description       = "SSH from the operator"
  cidr_ipv4         = var.operator_cidr
  ip_protocol       = "tcp"
  from_port         = 22
  to_port           = 22
}

resource "aws_vpc_security_group_ingress_rule" "fleet" {
  security_group_id            = aws_security_group.fleet.id
  description                  = "Everything between members of the fleet"
  referenced_security_group_id = aws_security_group.fleet.id
  ip_protocol                  = "-1"
}

resource "aws_vpc_security_group_egress_rule" "all" {
  security_group_id = aws_security_group.fleet.id
  description       = "Packages, and everything between members of the fleet"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

resource "aws_placement_group" "cluster" {
  count    = var.placement_group ? 1 : 0
  name     = var.name
  strategy = "cluster"
}

resource "aws_key_pair" "operator" {
  count      = var.ssh_public_key != "" ? 1 : 0
  key_name   = var.key_name
  public_key = var.ssh_public_key
}

resource "aws_instance" "machine" {
  for_each = local.machines

  ami                    = data.aws_ami.ubuntu.id
  instance_type          = each.value.type
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.fleet.id]
  key_name               = local.key_name
  placement_group        = var.placement_group ? aws_placement_group.cluster[0].id : null

  user_data = templatefile("${path.module}/user-data.sh.tftpl", {
    name     = each.key
    role     = each.value.role
    hostprep = base64encode(file("${path.module}/../../hostprep.sh"))
  })

  root_block_device {
    volume_size = var.root_volume_gb
    volume_type = "gp3"
  }

  metadata_options {
    http_tokens = "required"
  }

  tags = {
    Name = "${var.name}-${each.key}"
    Role = each.value.role
  }
}
