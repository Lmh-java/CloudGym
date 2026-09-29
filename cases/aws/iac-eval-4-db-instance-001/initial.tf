# Pre-existing: the application network the databases are placed into — the VPC
# 10.0.0.0/24, the internet gateway already attached to it, and the single subnet the
# account has carved out of that range so far. DNS support and DNS hostnames are on, as
# they must be for anything in this VPC to resolve names privately or to be given a
# public endpoint, and the gateway is attached because RDS refuses to place a publicly
# accessible instance in a VPC without one.
#
# Nothing of the task exists at S0: the VPC holds one subnet, so no DB subnet group is
# possible yet, and there is no database, no hosted zone and no record. The split-horizon
# answer the task asks for is absent in both directions, and the upper half of the VPC's
# address range is entirely unallocated.

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/24"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "app-vpc"
  }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "app-igw"
  }
}

resource "aws_subnet" "maina" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.0.0/25"
  availability_zone = data.aws_availability_zones.available.names[0]

  tags = {
    Name = "app-subnet-a"
  }
}
