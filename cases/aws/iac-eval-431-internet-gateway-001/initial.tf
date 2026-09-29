# Pre-existing: the dgraph workload's network and the one segment already running in it.
# The VPC is dedicated tenancy with DNS support and DNS hostnames on, and it carries the
# attribution the network is charged under; the core segment repeats it. S0 is the exemplar
# for "what stands in this network carries the marks the network carries" — Name is
# per-resource, the attribution is not.
#
# Nothing in the network has a path out at S0: no internet gateway exists anywhere near it,
# no route table in it carries a default route (the core segment rides the VPC's main table,
# which holds only the local route), and there is no explicit route table association at
# all. No gateway is kept by the account, no segment is held to an internal path, and
# nothing in the network carries a mark of anyone else's.

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
