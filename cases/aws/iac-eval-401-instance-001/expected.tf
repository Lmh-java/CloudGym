# IaC-Eval row 401, reference output rewritten against the pre-existing imaging network.
#
# Changes to the dataset reference: the `provider`/`terraform` blocks are dropped; the
# `terraform-aws-modules/vpc/aws` module is expanded into the plain VPC and subnets that
# already exist in initial.tf (an external module is not an input the harness can apply);
# the reference's two security groups are collapsed into the one group the serving hosts
# and the load balancer share, keeping the reference's separate ingress and egress rule
# resources; and the load balancer is internal rather than internet-facing, because the
# pre-existing network has no internet gateway and the task never asks for one. Everything
# the dataset row's intent names is unchanged: one `aws_lb` of type `application` given
# `subnets`, more than two `aws_subnet` with `cidr_block` inside one `aws_vpc` with
# `cidr_block`, one `aws_lb_listener` with a `load_balancer_arn` and a single `forward`
# default action, one `aws_lb_target_group` with port, protocol and `vpc_id`,
# `aws_lb_target_group_attachment` with `target_group_arn` and `target_id`, and
# `aws_instance` with `ami` and `instance_type`.
#
# The clean witness of the main intent with nobody else acting: two t2.micro serving hosts
# in the network's serving subnets, an internal application load balancer spanning all three
# of them, an HTTP:80 instance target group in imaging-vpc holding exactly those two hosts on
# port 80, an HTTP:80 listener whose only default action forwards to it, and one security
# group through which the hosts answer the load balancer on port 80. With nobody else acting
# the account keeps nothing for this workload's traffic and claims none of its space, so the
# front is the agent's own throughout: its own group in front of the hosts, its own target
# group, and all three serving subnets spanned.

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

resource "aws_security_group" "serving" {
  name        = "imaging-serving-sg"
  description = "imaging serving tier: HTTP from inside the network"
  vpc_id      = aws_vpc.imaging.id

  tags = {
    Name        = "imaging-serving-sg"
    Application = "imaging"
  }
}

resource "aws_vpc_security_group_ingress_rule" "serving_http" {
  security_group_id = aws_security_group.serving.id
  from_port         = 80
  to_port           = 80
  ip_protocol       = "tcp"
  cidr_ipv4         = aws_vpc.imaging.cidr_block
}

resource "aws_vpc_security_group_egress_rule" "serving_all" {
  security_group_id = aws_security_group.serving.id
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_instance" "serving_1" {
  ami                    = data.aws_ami.al2023.id
  instance_type          = "t2.micro"
  subnet_id              = aws_subnet.serving_a.id
  vpc_security_group_ids = [aws_security_group.serving.id]

  tags = {
    Name        = "imaging-serving-1"
    Application = "imaging"
  }
}

resource "aws_instance" "serving_2" {
  ami                    = data.aws_ami.al2023.id
  instance_type          = "t2.micro"
  subnet_id              = aws_subnet.serving_b.id
  vpc_security_group_ids = [aws_security_group.serving.id]

  tags = {
    Name        = "imaging-serving-2"
    Application = "imaging"
  }
}

resource "aws_lb" "imaging" {
  name               = "imaging-serving-alb"
  internal           = true
  load_balancer_type = "application"
  security_groups    = [aws_security_group.serving.id]
  subnets            = [aws_subnet.serving_a.id, aws_subnet.serving_b.id, aws_subnet.serving_c.id]

  tags = {
    Name        = "imaging-serving-alb"
    Application = "imaging"
  }
}

resource "aws_lb_target_group" "imaging" {
  name        = "imaging-serving-http-80"
  port        = 80
  protocol    = "HTTP"
  target_type = "instance"
  vpc_id      = aws_vpc.imaging.id

  tags = {
    Name        = "imaging-serving-http-80"
    Application = "imaging"
  }
}

resource "aws_lb_listener" "imaging" {
  load_balancer_arn = aws_lb.imaging.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.imaging.arn
  }
}

resource "aws_lb_target_group_attachment" "serving_1" {
  target_group_arn = aws_lb_target_group.imaging.arn
  target_id        = aws_instance.serving_1.id
  port             = 80
}

resource "aws_lb_target_group_attachment" "serving_2" {
  target_group_arn = aws_lb_target_group.imaging.arn
  target_id        = aws_instance.serving_2.id
  port             = 80
}
