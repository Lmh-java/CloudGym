# IaC-Eval row 394, reference output rewritten against the pre-existing catalog network.
#
# Changes to the dataset reference: the `provider`/`terraform` blocks are dropped; the
# `terraform-aws-modules/vpc/aws` module is expanded into the plain VPC and subnets that
# already exist in initial.tf (an external module is not an input the harness can apply);
# the reference's two security groups are collapsed into the one group the servers and the
# load balancer share, keeping the reference's separate ingress and egress rule resources;
# and the load balancer is internal rather than internet-facing, because the pre-existing
# network has no internet gateway and the task never asks for one. Everything the dataset
# row's intent names is unchanged: one `aws_lb` of type `application` given `subnets`, more
# than two `aws_subnet` with `cidr_block` inside one `aws_vpc` with `cidr_block`, one
# `aws_lb_listener` with a `load_balancer_arn` and a single `forward` default action, one
# `aws_lb_target_group` with port, protocol and `vpc_id`, `aws_lb_target_group_attachment`
# with `target_group_arn` and `target_id`, and `aws_instance` with `ami` and
# `instance_type`.
#
# The clean witness of the main intent with nobody else acting: two t2.micro servers in the
# catalog application's web tier, an internal application load balancer spanning that tier,
# an HTTP:80 instance target group in catalog-vpc, an HTTP:80 listener forwarding to it, and
# the catalog application's web servers in service registered in the group — which, with no
# other principal acting, are the two servers this file launches, and the tier is the three
# subnets that carry the application's attribution and the web-tier marking at S0, none of
# them held out of service or claimed by another owner.

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

resource "aws_vpc" "catalog" {
  cidr_block           = "10.60.0.0/16"
  enable_dns_hostnames = true

  tags = {
    Name     = "catalog-vpc"
    Workload = "catalog"
  }
}

resource "aws_subnet" "web_a" {
  vpc_id            = aws_vpc.catalog.id
  cidr_block        = "10.60.1.0/24"
  availability_zone = data.aws_availability_zones.available.names[0]

  tags = {
    Name     = "catalog-web-a"
    Tier     = "web"
    Workload = "catalog"
  }
}

resource "aws_subnet" "web_b" {
  vpc_id            = aws_vpc.catalog.id
  cidr_block        = "10.60.2.0/24"
  availability_zone = data.aws_availability_zones.available.names[1]

  tags = {
    Name     = "catalog-web-b"
    Tier     = "web"
    Workload = "catalog"
  }
}

resource "aws_subnet" "web_c" {
  vpc_id            = aws_vpc.catalog.id
  cidr_block        = "10.60.3.0/24"
  availability_zone = data.aws_availability_zones.available.names[2]

  tags = {
    Name     = "catalog-web-c"
    Tier     = "web"
    Workload = "catalog"
  }
}

resource "aws_security_group" "web" {
  name        = "catalog-web-sg"
  description = "catalog web tier: HTTP from inside the network"
  vpc_id      = aws_vpc.catalog.id

  tags = {
    Name     = "catalog-web-sg"
    Workload = "catalog"
  }
}

resource "aws_vpc_security_group_ingress_rule" "web_http" {
  security_group_id = aws_security_group.web.id
  from_port         = 80
  to_port           = 80
  ip_protocol       = "tcp"
  cidr_ipv4         = aws_vpc.catalog.cidr_block
}

resource "aws_vpc_security_group_egress_rule" "web_all" {
  security_group_id = aws_security_group.web.id
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_instance" "web_1" {
  ami                    = data.aws_ami.al2023.id
  instance_type          = "t2.micro"
  subnet_id              = aws_subnet.web_a.id
  vpc_security_group_ids = [aws_security_group.web.id]

  tags = {
    Name     = "catalog-web-1"
    Workload = "catalog"
  }
}

resource "aws_instance" "web_2" {
  ami                    = data.aws_ami.al2023.id
  instance_type          = "t2.micro"
  subnet_id              = aws_subnet.web_b.id
  vpc_security_group_ids = [aws_security_group.web.id]

  tags = {
    Name     = "catalog-web-2"
    Workload = "catalog"
  }
}

resource "aws_lb" "catalog" {
  name               = "catalog-web-alb"
  internal           = true
  load_balancer_type = "application"
  security_groups    = [aws_security_group.web.id]
  subnets            = [aws_subnet.web_a.id, aws_subnet.web_b.id, aws_subnet.web_c.id]

  tags = {
    Name     = "catalog-web-alb"
    Workload = "catalog"
  }
}

resource "aws_lb_target_group" "catalog" {
  name        = "catalog-web-http-80"
  port        = 80
  protocol    = "HTTP"
  target_type = "instance"
  vpc_id      = aws_vpc.catalog.id

  tags = {
    Name     = "catalog-web-http-80"
    Workload = "catalog"
  }
}

resource "aws_lb_listener" "catalog" {
  load_balancer_arn = aws_lb.catalog.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.catalog.arn
  }
}

resource "aws_lb_target_group_attachment" "web_1" {
  target_group_arn = aws_lb_target_group.catalog.arn
  target_id        = aws_instance.web_1.id
  port             = 80
}

resource "aws_lb_target_group_attachment" "web_2" {
  target_group_arn = aws_lb_target_group.catalog.arn
  target_id        = aws_instance.web_2.id
  port             = 80
}
