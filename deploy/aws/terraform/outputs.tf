locals {
  described = {
    for name, i in aws_instance.machine : name => {
      name       = name
      public_ip  = i.public_ip
      private_ip = i.private_ip
    }
  }
}

output "fleet" {
  description = "Every machine's role and addresses, with the region and instance types: what wirenet-lab reads from `terraform output -json`."
  value = {
    region   = var.region
    ssh_user = "ubuntu"
    instance_types = {
      cp     = var.cp_instance_type
      agent  = var.agent_instance_type
      relay  = var.relay_instance_type
      middle = var.middle_instance_type
    }
    cp     = local.described["cp"]
    middle = local.described["mid"]
    agents = [for n in local.agent_names : local.described[n]]
    relays = [for n in local.relay_names : local.described[n]]
  }
}

output "ami" {
  description = "The Ubuntu 24.04 image every machine runs."
  value       = data.aws_ami.ubuntu.id
}
