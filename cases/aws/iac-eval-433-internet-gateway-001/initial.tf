# Pre-existing: the platform team's own network, the one the account already runs shared
# work in. It is the network the new workload's network will stand beside.
#
# Nothing in the account has a way out at S0: no internet gateway of the case's own exists,
# the platform network carries no segment, holds only the main table EC2 created with it
# (not declared here; it carries the local route and nothing else), nothing in it carries a
# default route, and nothing in it carries a mark of anyone else's. The workload's own
# network — the 10.0.0.0/16 one — does not exist yet, and neither does any gateway or table
# for it.

resource "aws_vpc" "platform" {
  cidr_block           = "10.70.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name     = "platform-vpc"
    Workload = "platform"
  }
}
