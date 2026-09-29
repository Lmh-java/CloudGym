# IaC-Eval row 388, reference output rewritten against the pre-existing checkout network
# (provider/terraform blocks dropped, the reference's VPC and subnet replaced by the ones that
# already exist in initial.tf, the load balancer type corrected from "application" to the
# network load balancer the prompt asks for, and the listener and target group moved to TCP as
# a network load balancer requires).
#
# The clean witness of the main intent with nobody else acting: one t2.micro server in the
# checkout service's front subnet, an internal network load balancer in that same subnet, a
# TCP:80 instance target group in checkout-vpc, a TCP:80 listener forwarding to it, and the
# service's serving instances registered in the group — which, with no other principal acting,
# is the one server this file launches.

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

resource "aws_instance" "checkout_web" {
  ami           = data.aws_ami.al2023.id
  instance_type = "t2.micro"
  subnet_id     = aws_subnet.front_a.id

  tags = {
    Name     = "checkout-web-1"
    Workload = "checkout"
  }
}

resource "aws_lb" "checkout" {
  name               = "checkout-front-nlb"
  internal           = true
  load_balancer_type = "network"
  subnets            = [aws_subnet.front_a.id]

  tags = {
    Name     = "checkout-front-nlb"
    Workload = "checkout"
  }
}

resource "aws_lb_target_group" "checkout" {
  name        = "checkout-front-tcp-80"
  port        = 80
  protocol    = "TCP"
  target_type = "instance"
  vpc_id      = aws_vpc.checkout.id

  tags = {
    Name     = "checkout-front-tcp-80"
    Workload = "checkout"
  }
}

resource "aws_lb_listener" "checkout" {
  load_balancer_arn = aws_lb.checkout.arn
  port              = "80"
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.checkout.arn
  }
}

resource "aws_lb_target_group_attachment" "checkout" {
  target_group_arn = aws_lb_target_group.checkout.arn
  target_id        = aws_instance.checkout_web.id
  port             = 80
}
