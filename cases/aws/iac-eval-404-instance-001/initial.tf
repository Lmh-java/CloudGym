# Pre-existing: the storefront application's network and nothing else. A VPC on
# 10.60.0.0/16 with three public subnets in distinct availability zones, an internet
# gateway and a default route through it, so the network can already carry public
# traffic. Nothing serves that traffic yet: the account holds no load balancer, no
# target group, no listener and no server, and the network's only security group is
# the one the VPC brings with it.

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_vpc" "storefront" {
  cidr_block           = "10.60.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "storefront-vpc"
    App  = "storefront"
  }
}

resource "aws_subnet" "public" {
  count                   = 3
  vpc_id                  = aws_vpc.storefront.id
  cidr_block              = cidrsubnet(aws_vpc.storefront.cidr_block, 8, count.index + 1)
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true

  tags = {
    Name = "storefront-public-${count.index + 1}"
    Tier = "public"
    App  = "storefront"
  }
}

resource "aws_internet_gateway" "storefront" {
  vpc_id = aws_vpc.storefront.id

  tags = {
    Name = "storefront-igw"
    App  = "storefront"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.storefront.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.storefront.id
  }

  tags = {
    Name = "storefront-public-rt"
    App  = "storefront"
  }
}

resource "aws_route_table_association" "public" {
  count          = 3
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}
