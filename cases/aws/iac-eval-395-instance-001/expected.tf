# IaC-Eval row 395, reference output rewritten against the pre-existing ledger network
# (provider/terraform blocks dropped, the reference's VPC module and its subnets replaced by the
# network that already exists in initial.tf, the internet-facing load balancer made internal —
# the network has no gateway — and the security groups of the reference dropped with it).
#
# The clean witness of the main intent with nobody else acting: one t2.micro server in each of
# the ledger service's front segments, an internal network load balancer standing across those
# same two segments, a TCP:80 instance target group in ledger-vpc, a TCP:80 listener forwarding
# to it, and the service's serving instances registered in the group on port 80 — which, with no
# other principal acting, are the two servers this file launches.

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

resource "aws_vpc" "ledger" {
  cidr_block           = "10.40.0.0/16"
  enable_dns_hostnames = true

  tags = {
    Name     = "ledger-vpc"
    Workload = "ledger"
  }
}

resource "aws_subnet" "front_a" {
  vpc_id            = aws_vpc.ledger.id
  cidr_block        = "10.40.1.0/24"
  availability_zone = data.aws_availability_zones.available.names[0]

  tags = {
    Name     = "ledger-front-a"
    Segment  = "front"
    Workload = "ledger"
  }
}

resource "aws_subnet" "front_b" {
  vpc_id            = aws_vpc.ledger.id
  cidr_block        = "10.40.2.0/24"
  availability_zone = data.aws_availability_zones.available.names[1]

  tags = {
    Name     = "ledger-front-b"
    Segment  = "front"
    Workload = "ledger"
  }
}

resource "aws_instance" "ledger_web_a" {
  ami           = data.aws_ami.al2023.id
  instance_type = "t2.micro"
  subnet_id     = aws_subnet.front_a.id

  tags = {
    Name     = "ledger-web-1"
    Workload = "ledger"
  }
}

resource "aws_instance" "ledger_web_b" {
  ami           = data.aws_ami.al2023.id
  instance_type = "t2.micro"
  subnet_id     = aws_subnet.front_b.id

  tags = {
    Name     = "ledger-web-2"
    Workload = "ledger"
  }
}

resource "aws_lb" "ledger" {
  name               = "ledger-front-nlb"
  internal           = true
  load_balancer_type = "network"
  subnets            = [aws_subnet.front_a.id, aws_subnet.front_b.id]

  tags = {
    Name     = "ledger-front-nlb"
    Workload = "ledger"
  }
}

resource "aws_lb_target_group" "ledger" {
  name        = "ledger-front-tcp-80"
  port        = 80
  protocol    = "TCP"
  target_type = "instance"
  vpc_id      = aws_vpc.ledger.id

  tags = {
    Name     = "ledger-front-tcp-80"
    Workload = "ledger"
  }
}

resource "aws_lb_listener" "ledger" {
  load_balancer_arn = aws_lb.ledger.arn
  port              = "80"
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.ledger.arn
  }
}

resource "aws_lb_target_group_attachment" "ledger_web_a" {
  target_group_arn = aws_lb_target_group.ledger.arn
  target_id        = aws_instance.ledger_web_a.id
  port             = 80
}

resource "aws_lb_target_group_attachment" "ledger_web_b" {
  target_group_arn = aws_lb_target_group.ledger.arn
  target_id        = aws_instance.ledger_web_b.id
  port             = 80
}
