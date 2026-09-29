# Pre-existing: the imaging application's network and its three serving subnets, one per
# zone — the space anything answering imaging traffic runs in.
#
# Nothing in the network is load-balanced and nothing runs in it: at S0 the VPC holds no
# instance, no security group of its own, no load balancer, no target group and no
# listener. Every subnet carries the imaging application's attribution and the serving
# marking and is the application's own — none is claimed by another owner — the account
# keeps nothing of its own for this workload's traffic, and no host anywhere in the
# account serves it.

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_vpc" "imaging" {
  cidr_block           = "10.80.0.0/16"
  enable_dns_hostnames = true

  tags = {
    Name        = "imaging-vpc"
    Application = "imaging"
  }
}

resource "aws_subnet" "serving_a" {
  vpc_id            = aws_vpc.imaging.id
  cidr_block        = "10.80.11.0/24"
  availability_zone = data.aws_availability_zones.available.names[0]

  tags = {
    Name        = "imaging-serving-a"
    Role        = "serving"
    Application = "imaging"
  }
}

resource "aws_subnet" "serving_b" {
  vpc_id            = aws_vpc.imaging.id
  cidr_block        = "10.80.12.0/24"
  availability_zone = data.aws_availability_zones.available.names[1]

  tags = {
    Name        = "imaging-serving-b"
    Role        = "serving"
    Application = "imaging"
  }
}

resource "aws_subnet" "serving_c" {
  vpc_id            = aws_vpc.imaging.id
  cidr_block        = "10.80.13.0/24"
  availability_zone = data.aws_availability_zones.available.names[2]

  tags = {
    Name        = "imaging-serving-c"
    Role        = "serving"
    Application = "imaging"
  }
}
