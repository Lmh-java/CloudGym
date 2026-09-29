# Pre-existing: the storefront workload's network, the private subnet already running in
# it, and the route table the account keeps that network's routing on.
#
# Nothing in the VPC has a path out: at S0 there is no internet gateway anywhere near it,
# no default route on any table in it, and no explicit subnet association at all — the
# private subnet rides the VPC's main table. The kept table carries only the local route.
# No segment is held out of service and nothing in the VPC belongs to anyone else.

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_vpc" "app" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true

  tags = {
    Name     = "app-vpc"
    Workload = "storefront"
  }
}

resource "aws_subnet" "private_a" {
  vpc_id            = aws_vpc.app.id
  cidr_block        = "10.0.10.0/24"
  availability_zone = data.aws_availability_zones.available.names[0]

  tags = {
    Name     = "app-private-a"
    Tier     = "private"
    Workload = "storefront"
  }
}

resource "aws_route_table" "shared" {
  vpc_id = aws_vpc.app.id

  tags = {
    Name     = "app-shared-rt"
    Routing  = "shared"
    Workload = "storefront"
  }
}
