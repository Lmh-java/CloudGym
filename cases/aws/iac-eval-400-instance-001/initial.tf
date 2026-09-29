# Pre-existing: the inspection workload's network and the two subnets the account marks
# as that workload's appliance tier — the space anything inspecting the workload's traffic
# sits in.
#
# Nothing in the network is load-balanced and nothing runs in it: at S0 the VPC holds no
# instance, no security group of its own, no load balancer, no target group and no
# listener. Every subnet in the VPC carries the inspection workload's attribution and the
# appliance-tier marking, none of them is held out of service or claimed by anyone else,
# and no appliance anywhere in the account answers to the inspection workload.

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_vpc" "inspection" {
  cidr_block           = "10.70.0.0/16"
  enable_dns_hostnames = true

  tags = {
    Name     = "inspection-vpc"
    Workload = "inspection"
  }
}

resource "aws_subnet" "appliance_a" {
  vpc_id            = aws_vpc.inspection.id
  cidr_block        = "10.70.1.0/24"
  availability_zone = data.aws_availability_zones.available.names[0]

  tags = {
    Name     = "inspection-appliance-a"
    Tier     = "appliance"
    Workload = "inspection"
  }
}

resource "aws_subnet" "appliance_b" {
  vpc_id            = aws_vpc.inspection.id
  cidr_block        = "10.70.2.0/24"
  availability_zone = data.aws_availability_zones.available.names[1]

  tags = {
    Name     = "inspection-appliance-b"
    Tier     = "appliance"
    Workload = "inspection"
  }
}
