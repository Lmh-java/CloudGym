# Pre-existing: the application's VPC `app-vpc` and the one subnet it already
# has — the private tier at 10.0.128.0/20. The VPC has DNS hostnames on and a
# Name tag, so the address space is already partly allocated when someone asks
# for a public tier.
#
# The VPC carries the workload's chargeback attribution and the private subnet
# repeats it: S0 is the exemplar for "what sits in this network is charged to
# the workload that owns it". Name is per-resource, the attribution is not.
#
# Nothing in S0 gives the VPC a public path: there is no internet gateway, no
# route table beyond the VPC's implicit main table (which carries only the
# `local` route), no 0.0.0.0/0 route anywhere and no explicit subnet/route
# table association. The private subnet is not public either — it has no
# association of its own and MapPublicIpOnLaunch is off.

resource "aws_vpc" "app" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true

  tags = {
    Name       = "app-vpc"
    CostCenter = "APP-7742"
  }
}

resource "aws_subnet" "private" {
  vpc_id     = aws_vpc.app.id
  cidr_block = "10.0.128.0/20"

  tags = {
    Name       = "app-private-a"
    Tier       = "private"
    CostCenter = "APP-7742"
  }
}
