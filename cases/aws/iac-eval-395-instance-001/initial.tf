# Pre-existing: the ledger service's network — the VPC on 10.40.0.0/16 and the two front
# segments the service's servers run in, all three carrying the service's attribution. Nothing
# runs in the network yet and nothing in it is load-balanced: at S0 the VPC holds no instance,
# no load balancer, no target group and no listener, and the account holds no other server that
# answers to the ledger service.

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_vpc" "ledger" {
  cidr_block           = "10.40.0.0/16"
  enable_dns_hostnames = true

  tags = {
    Name     = "ledger-vpc"
    Workload = "ledger"
  }
}

resource "aws_subnet" "front_a" {
  vpc_id            = aws_vpc.ledger.id
  cidr_block        = "10.40.1.0/24"
  availability_zone = data.aws_availability_zones.available.names[0]

  tags = {
    Name     = "ledger-front-a"
    Segment  = "front"
    Workload = "ledger"
  }
}

resource "aws_subnet" "front_b" {
  vpc_id            = aws_vpc.ledger.id
  cidr_block        = "10.40.2.0/24"
  availability_zone = data.aws_availability_zones.available.names[1]

  tags = {
    Name     = "ledger-front-b"
    Segment  = "front"
    Workload = "ledger"
  }
}
