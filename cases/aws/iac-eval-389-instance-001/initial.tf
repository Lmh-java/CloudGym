# Pre-existing: the orders service's network, the server that runs in it, and the group cut for
# that server — the VPC tagged Name=orders-vpc on 10.40.0.0/16, its two edge subnets in two
# zones, the application server orders-app-1 in the first of them, and orders-app-sg.
#
# Nothing in this VPC is reachable from the internet at S0 and nothing balances traffic to it:
# no internet gateway is attached, the edge subnets have no route-table association of their
# own (they still follow the VPC's main table, which carries only the local route), and the
# account holds no load balancer, no target group and no listener at all. orders-app-sg stands
# but does nothing yet: it is on no server and admits nothing inbound, because what would reach
# the server through it does not exist. The server carries the workload's attribution and still
# sits in the VPC's default group; the load balancer and its own group do not exist yet.

data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-x86_64"]
  }
}

resource "aws_vpc" "orders" {
  cidr_block           = "10.40.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name     = "orders-vpc"
    Workload = "orders"
  }
}

resource "aws_subnet" "edge_a" {
  vpc_id            = aws_vpc.orders.id
  cidr_block        = "10.40.1.0/24"
  availability_zone = data.aws_availability_zones.available.names[0]

  tags = {
    Name     = "orders-edge-a"
    Tier     = "edge"
    Workload = "orders"
  }
}

resource "aws_subnet" "edge_b" {
  vpc_id            = aws_vpc.orders.id
  cidr_block        = "10.40.2.0/24"
  availability_zone = data.aws_availability_zones.available.names[1]

  tags = {
    Name     = "orders-edge-b"
    Tier     = "edge"
    Workload = "orders"
  }
}

resource "aws_instance" "app" {
  ami           = data.aws_ami.al2023.id
  instance_type = "t2.micro"
  subnet_id     = aws_subnet.edge_a.id

  tags = {
    Name     = "orders-app-1"
    Workload = "orders"
  }
}

# The server's own group, standing empty: it admits nothing inbound and is on no instance.
resource "aws_security_group" "app" {
  name        = "orders-app-sg"
  description = "orders application server"
  vpc_id      = aws_vpc.orders.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name     = "orders-app-sg"
    Workload = "orders"
  }
}
