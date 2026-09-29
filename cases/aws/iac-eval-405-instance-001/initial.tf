# Pre-existing: the network the workload is placed into — the application VPC
# `app-vpc` (10.0.0.0/16) and its two application subnets, one per availability
# zone. Nothing of the task exists at S0: no EC2 instance, no security group of
# the application's own, no load balancer, no target group, no listener and no
# registered target. The VPC has no internet gateway, so the load balancer the
# task asks for is an internal one. The VPC carries the workload's attribution
# (Owner / CostCenter); nothing in the diff carries it yet.

resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name       = "app-vpc"
    Owner      = "storefront-team"
    CostCenter = "APP-2718"
  }
}

resource "aws_subnet" "app_a" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.4.0/24"
  availability_zone = "us-east-1a"

  tags = {
    Name = "app-a"
    Tier = "application"
  }
}

resource "aws_subnet" "app_b" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.5.0/24"
  availability_zone = "us-east-1b"

  tags = {
    Name = "app-b"
    Tier = "application"
  }
}
