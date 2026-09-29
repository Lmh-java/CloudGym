# IaC-Eval reference output for row 428 (provider/terraform blocks dropped; the
# reference's `count`/CIDR-list indirection expanded into explicit blocks, and
# its inline `route {}` block written as a standalone `aws_route` so the default
# route is part of the observed type set — Cloud Control's
# AWS::EC2::RouteTable model does not carry routes).
#
# The VPC and the private subnet are the pre-existing part (see initial.tf); the
# two public subnets, the internet gateway, the public route table, its default
# route and the two associations are the task.

data "aws_availability_zones" "available" {
  state = "available"
}

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

resource "aws_subnet" "public_a" {
  vpc_id            = aws_vpc.app.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = data.aws_availability_zones.available.names[0]

  tags = {
    Name       = "app-public-a"
    Tier       = "public"
    CostCenter = "APP-7742"
  }
}

resource "aws_subnet" "public_b" {
  vpc_id            = aws_vpc.app.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = data.aws_availability_zones.available.names[1]

  tags = {
    Name       = "app-public-b"
    Tier       = "public"
    CostCenter = "APP-7742"
  }
}

resource "aws_internet_gateway" "app" {
  vpc_id = aws_vpc.app.id

  tags = {
    Name       = "app-igw"
    CostCenter = "APP-7742"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.app.id

  tags = {
    Name       = "app-public-rt"
    CostCenter = "APP-7742"
  }
}

resource "aws_route" "public_default" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.app.id
}

resource "aws_route_table_association" "public_a" {
  subnet_id      = aws_subnet.public_a.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "public_b" {
  subnet_id      = aws_subnet.public_b.id
  route_table_id = aws_route_table.public.id
}
