# Pre-existing: the network the Windows workload runs in — the VPC
# `windomain-vpc` (192.168.0.0/16). Nothing customises how that VPC resolves
# names yet: at S0 it still carries the account's default DHCP options set,
# there is no DHCP options set of the workload's own and no association
# between one and the VPC.

resource "aws_vpc" "default" {
  cidr_block = "192.168.0.0/16"

  tags = {
    Name = "windomain-vpc"
  }
}
