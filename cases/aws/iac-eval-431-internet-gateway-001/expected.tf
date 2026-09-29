# IaC-Eval reference output for row 431 (provider/terraform blocks dropped; the variable
# the reference tags with is inlined as a concrete Name; the table's inline route hoisted
# into an aws_route so the route's target is observable; the pre-existing network and its
# core segment are carried over from initial.tf unchanged).
#
# The clean witness of the task alone: the network gets a gateway of its own and a table
# whose default route leaves through it. It is not the resolved outcome when the account
# already keeps a gateway for that purpose.

resource "aws_vpc" "dgraph" {
  cidr_block           = "10.60.0.0/16"
  instance_tenancy     = "dedicated"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name       = "dgraph-vpc"
    Workload   = "dgraph"
    CostCenter = "DGR-4402"
  }
}

resource "aws_subnet" "core_a" {
  vpc_id     = aws_vpc.dgraph.id
  cidr_block = "10.60.10.0/24"

  tags = {
    Name       = "dgraph-core-a"
    Tier       = "core"
    Workload   = "dgraph"
    CostCenter = "DGR-4402"
  }
}

resource "aws_internet_gateway" "dgraph_gw" {
  vpc_id = aws_vpc.dgraph.id

  tags = {
    Name = "dgraph-igw"
  }
}

resource "aws_route_table" "dgraph_igw" {
  vpc_id = aws_vpc.dgraph.id

  tags = {
    Name = "dgraph-public-rt"
  }
}

resource "aws_route" "dgraph_default" {
  route_table_id         = aws_route_table.dgraph_igw.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.dgraph_gw.id
}
