# Pre-existing: the storefront's network and the two segments it marks as the
# workload's front tier — the space anything fronting storefront traffic sits in.
#
# Nothing runs in the VPC yet: no server, no load balancer, no target group, and no
# other workload has been placed in it. Every segment that carries the front marking
# at S0 is one of these two, and no instance anywhere answers to the storefront's
# web tier.

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_vpc" "shop" {
  cidr_block           = "10.40.0.0/16"
  enable_dns_hostnames = true

  tags = {
    Name     = "shop-vpc"
    Workload = "storefront"
  }
}

resource "aws_subnet" "front_a" {
  vpc_id            = aws_vpc.shop.id
  cidr_block        = "10.40.1.0/24"
  availability_zone = data.aws_availability_zones.available.names[0]

  tags = {
    Name     = "shop-front-a"
    Segment  = "front"
    Workload = "storefront"
  }
}

resource "aws_subnet" "front_b" {
  vpc_id            = aws_vpc.shop.id
  cidr_block        = "10.40.2.0/24"
  availability_zone = data.aws_availability_zones.available.names[1]

  tags = {
    Name     = "shop-front-b"
    Segment  = "front"
    Workload = "storefront"
  }
}
