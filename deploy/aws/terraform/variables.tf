variable "name" {
  description = "Prefixes every resource's Name tag, so two fleets can share an account."
  type        = string
  default     = "wirenet-bench"
}

variable "region" {
  description = "AWS region."
  type        = string
  default     = "us-east-1"
}

variable "availability_zone" {
  description = "The availability zone for the subnet; the region's first when empty."
  type        = string
  default     = ""
}

variable "operator_cidr" {
  description = "The only addresses SSH accepts, such as your own address as a /32."
  type        = string

  validation {
    condition     = can(cidrhost(var.operator_cidr, 0))
    error_message = "operator_cidr must be a CIDR block, such as 203.0.113.7/32."
  }
}

variable "key_name" {
  description = "The EC2 key pair every instance accepts for SSH."
  type        = string
}

variable "ssh_public_key" {
  description = "When set, creates the key pair named key_name from this public key; otherwise key_name must already exist."
  type        = string
  default     = ""
}

variable "vpc_cidr" {
  description = "The VPC's address range."
  type        = string
  default     = "10.60.0.0/16"
}

variable "subnet_cidr" {
  description = "The public subnet's address range, inside vpc_cidr."
  type        = string
  default     = "10.60.1.0/24"
}

variable "placement_group" {
  description = "Places every instance in one cluster placement group, for the lowest and steadiest latency between them."
  type        = bool
  default     = false
}

variable "agent_count" {
  description = "Agent hosts. The plans need at least 2."
  type        = number
  default     = 3

  validation {
    condition     = var.agent_count >= 2
    error_message = "The plans need at least 2 agent hosts."
  }
}

variable "relay_count" {
  description = "Relays, besides the middle box. Failover needs at least 2."
  type        = number
  default     = 2

  validation {
    condition     = var.relay_count >= 2
    error_message = "Failover needs at least 2 relays."
  }
}

variable "cp_instance_type" {
  description = "The control-plane host's instance type; it runs Postgres and wirenet-cp."
  type        = string
  default     = "c6i.xlarge"
}

variable "agent_instance_type" {
  description = "The agent hosts' instance type."
  type        = string
  default     = "c6i.xlarge"
}

variable "relay_instance_type" {
  description = "The relays' instance type."
  type        = string
  default     = "c6i.xlarge"
}

variable "middle_instance_type" {
  description = "The middle box's instance type; it plays both the relay and the WireGuard-terminating gateway in the path comparison."
  type        = string
  default     = "c6i.xlarge"
}

variable "root_volume_gb" {
  description = "Root volume size on every instance."
  type        = number
  default     = 20
}
