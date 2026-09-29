# Pre-existing: the catalog application's network and the three subnets the account
# marks as that application's web tier — the space anything serving catalog web traffic
# sits in.
#
# Nothing in the network is load-balanced and nothing runs in it: at S0 the VPC holds no
# instance, no security group of its own, no load balancer, no target group and no
# listener. Every subnet in the VPC carries the catalog application's attribution and the
# web-tier marking, none of them is held out of service or claimed by anyone else, and no
# server anywhere in the account answers to the catalog application's web tier.

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_vpc" "catalog" {
  cidr_block           = "10.60.0.0/16"
  enable_dns_hostnames = true

  tags = {
    Name     = "catalog-vpc"
    Workload = "catalog"
  }
}

resource "aws_subnet" "web_a" {
  vpc_id            = aws_vpc.catalog.id
  cidr_block        = "10.60.1.0/24"
  availability_zone = data.aws_availability_zones.available.names[0]

  tags = {
    Name     = "catalog-web-a"
    Tier     = "web"
    Workload = "catalog"
  }
}

resource "aws_subnet" "web_b" {
  vpc_id            = aws_vpc.catalog.id
  cidr_block        = "10.60.2.0/24"
  availability_zone = data.aws_availability_zones.available.names[1]

  tags = {
    Name     = "catalog-web-b"
    Tier     = "web"
    Workload = "catalog"
  }
}

resource "aws_subnet" "web_c" {
  vpc_id            = aws_vpc.catalog.id
  cidr_block        = "10.60.3.0/24"
  availability_zone = data.aws_availability_zones.available.names[2]

  tags = {
    Name     = "catalog-web-c"
    Tier     = "web"
    Workload = "catalog"
  }
}
