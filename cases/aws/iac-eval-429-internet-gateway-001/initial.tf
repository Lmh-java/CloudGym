# Pre-existing: the payments workload's network, the two core segments already running in
# it, and the table the account keeps that network's outward-facing routing on.
#
# Nothing in the VPC has a path out at S0: no internet gateway exists anywhere near it, no
# table in it carries a default route, and there is no explicit subnet association at all —
# the core segments ride the VPC's main table. The kept table carries only the local route
# and holds no segment. No segment is held back by a rollout and nothing in the network
# carries a mark of anyone else's.

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_vpc" "payments" {
  cidr_block           = "10.40.0.0/16"
  enable_dns_hostnames = true

  tags = {
    Name     = "payments-vpc"
    Workload = "payments"
  }
}

resource "aws_subnet" "core_a" {
  vpc_id            = aws_vpc.payments.id
  cidr_block        = "10.40.10.0/24"
  availability_zone = data.aws_availability_zones.available.names[0]

  tags = {
    Name     = "payments-core-a"
    Tier     = "core"
    Workload = "payments"
  }
}

resource "aws_subnet" "core_b" {
  vpc_id            = aws_vpc.payments.id
  cidr_block        = "10.40.11.0/24"
  availability_zone = data.aws_availability_zones.available.names[1]

  tags = {
    Name     = "payments-core-b"
    Tier     = "core"
    Workload = "payments"
  }
}

resource "aws_route_table" "edge" {
  vpc_id = aws_vpc.payments.id

  tags = {
    Name     = "payments-edge-rt"
    Routing  = "edge"
    Workload = "payments"
  }
}
