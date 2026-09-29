# Pre-existing: the checkout service's network — the VPC on 10.30.0.0/16 and the one front
# subnet the service's servers run in, both carrying the service's attribution. Nothing runs
# in the network yet and nothing in it is load-balanced: at S0 the VPC holds no instance, no
# load balancer, no target group and no listener, and the account holds no other server that
# answers to the checkout service.

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_vpc" "checkout" {
  cidr_block           = "10.30.0.0/16"
  enable_dns_hostnames = true

  tags = {
    Name     = "checkout-vpc"
    Workload = "checkout"
  }
}

resource "aws_subnet" "front_a" {
  vpc_id            = aws_vpc.checkout.id
  cidr_block        = "10.30.1.0/24"
  availability_zone = data.aws_availability_zones.available.names[0]

  tags = {
    Name     = "checkout-front-a"
    Segment  = "front"
    Workload = "checkout"
  }
}
