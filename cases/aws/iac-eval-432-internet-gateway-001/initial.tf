# Pre-existing: the graph store's network and the one segment it runs outward-facing work in.
#
# The VPC is on dedicated tenancy, as the workload requires, but it neither resolves DNS nor
# hands out DNS hostnames yet, and the network has no way out at all: no internet gateway
# exists anywhere near it, nothing in it carries a default route, there is no explicit
# route-table association — the segment rides the VPC's main table — and nothing in the network
# carries a mark of anyone else's. The main table EC2 creates with a VPC is not declared here;
# it holds the local route and nothing else.

resource "aws_vpc" "dgraph" {
  cidr_block           = "10.30.0.0/16"
  instance_tenancy     = "dedicated"
  enable_dns_support   = false
  enable_dns_hostnames = false

  tags = {
    Name     = "dgraph-vpc"
    Workload = "dgraph"
  }
}

resource "aws_subnet" "edge" {
  vpc_id     = aws_vpc.dgraph.id
  cidr_block = "10.30.1.0/24"

  tags = {
    Name     = "dgraph-edge-a"
    Tier     = "edge"
    Workload = "dgraph"
  }
}
