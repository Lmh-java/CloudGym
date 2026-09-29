# IaC-Eval reference output for row 405, adapted to the sandbox: the `terraform`/`provider`
# blocks are dropped, the community VPC module is inlined as the plain `aws_vpc` / `aws_subnet`
# blocks of initial.tf (which pre-exist), and the load balancer is internal because the
# sandbox VPC has no internet gateway. Everything else follows the reference: an application
# load balancer across the two application subnets, an HTTP:80 listener whose default action
# forwards to a target group in the VPC, and the EC2 instance registered in that target group.
#
# This is the witness of the task carried out with nobody else acting on the account; it is
# never applied.

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

data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-x86_64"]
  }
}

resource "aws_security_group" "instance" {
  name   = "web-app-sg"
  vpc_id = aws_vpc.main.id
}

resource "aws_vpc_security_group_ingress_rule" "instance_http" {
  security_group_id            = aws_security_group.instance.id
  from_port                    = 80
  to_port                      = 80
  ip_protocol                  = "tcp"
  referenced_security_group_id = aws_security_group.lb.id
}

resource "aws_vpc_security_group_egress_rule" "instance_all" {
  security_group_id = aws_security_group.instance.id
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_instance" "web" {
  ami                    = data.aws_ami.al2023.id
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.app_a.id
  vpc_security_group_ids = [aws_security_group.instance.id]

  tags = {
    Name = "web-app"
  }
}

resource "aws_security_group" "lb" {
  name   = "web-alb-sg"
  vpc_id = aws_vpc.main.id
}

resource "aws_vpc_security_group_ingress_rule" "lb_http" {
  security_group_id = aws_security_group.lb.id
  from_port         = 80
  to_port           = 80
  ip_protocol       = "tcp"
  cidr_ipv4         = "10.0.0.0/16"
}

resource "aws_lb" "web" {
  name               = "web-alb"
  internal           = true
  load_balancer_type = "application"
  subnets            = [aws_subnet.app_a.id, aws_subnet.app_b.id]
  security_groups    = [aws_security_group.lb.id]
}

resource "aws_lb_target_group" "web" {
  name     = "web-tg"
  port     = 80
  protocol = "HTTP"
  vpc_id   = aws_vpc.main.id
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.web.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.web.arn
  }
}

# The same routing stated as a rule on the listener as well as its default action. The witness
# carries it so that listener rules are part of the observed resource set: routing a workload
# through a rule on an HTTP listener is the other realisation of "the listener routes to the
# target group", and the oracle accepts either.
resource "aws_lb_listener_rule" "web" {
  listener_arn = aws_lb_listener.http.arn
  priority     = 100

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.web.arn
  }

  condition {
    path_pattern {
      values = ["/*"]
    }
  }
}

resource "aws_lb_target_group_attachment" "web" {
  target_group_arn = aws_lb_target_group.web.arn
  target_id        = aws_instance.web.id
  port             = 80
}
