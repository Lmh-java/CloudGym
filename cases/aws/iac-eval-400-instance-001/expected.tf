# IaC-Eval row 400, reference output rewritten against the pre-existing inspection network.
#
# Changes to the dataset reference: the `provider`/`terraform` blocks are dropped; the
# `terraform-aws-modules/vpc/aws` module is expanded into the plain VPC and subnets that
# already exist in initial.tf (an external module is not an input the harness can apply);
# the image filter is pinned to an image family the sandbox region carries; and the
# appliance sits in the workload's appliance tier rather than in an arbitrary public
# subnet, because the pre-existing network has no internet gateway and the task never asks
# for one. Everything the dataset row's intent names is unchanged: one `aws_lb` of type
# `gateway` given `subnet_mapping`, two `aws_subnet` with `cidr_block` inside one `aws_vpc`
# with `cidr_block`, one `aws_lb_listener` with a `load_balancer_arn` and a default action
# carrying a `type`, one `aws_lb_target_group` with port, protocol and `vpc_id`, one
# `aws_lb_target_group_attachment` with `target_group_arn` and `target_id`, and one
# `aws_instance` with `ami` and `instance_type`.
#
# The clean witness of the main intent with nobody else acting: one t2.micro appliance in
# `10.70.1.0/24`, a Gateway Load Balancer spanning both appliance-tier subnets, a GENEVE:6081
# instance target group in inspection-vpc, a listener whose only default action forwards to
# it, and that appliance registered in the group on port 6081. With no other principal acting
# the account keeps no pool and no front for this traffic, so the agent's own are the only
# ones; nothing is held out of service and no segment is marked as the workload's place, so
# the appliance stands where the request named and the front spans the two segments that
# carry the workload's attribution and the appliance-tier marking at S0.

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

resource "aws_security_group" "appliance" {
  name        = "inspection-appliance-sg"
  description = "inspection appliance tier: GENEVE and health checks from inside the network"
  vpc_id      = aws_vpc.inspection.id

  tags = {
    Name     = "inspection-appliance-sg"
    Workload = "inspection"
  }
}

resource "aws_vpc_security_group_ingress_rule" "appliance_geneve" {
  security_group_id = aws_security_group.appliance.id
  from_port         = 6081
  to_port           = 6081
  ip_protocol       = "udp"
  cidr_ipv4         = aws_vpc.inspection.cidr_block
}

resource "aws_vpc_security_group_egress_rule" "appliance_all" {
  security_group_id = aws_security_group.appliance.id
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_instance" "appliance_1" {
  ami                    = data.aws_ami.al2023.id
  instance_type          = "t2.micro"
  subnet_id              = aws_subnet.appliance_a.id
  vpc_security_group_ids = [aws_security_group.appliance.id]

  tags = {
    Name     = "inspection-appliance-1"
    Workload = "inspection"
  }
}

resource "aws_lb" "inspection" {
  name               = "inspection-gwlb"
  load_balancer_type = "gateway"

  subnet_mapping {
    subnet_id = aws_subnet.appliance_a.id
  }

  subnet_mapping {
    subnet_id = aws_subnet.appliance_b.id
  }

  tags = {
    Name     = "inspection-gwlb"
    Workload = "inspection"
  }
}

resource "aws_lb_target_group" "inspection" {
  name        = "inspection-geneve-6081"
  port        = 6081
  protocol    = "GENEVE"
  target_type = "instance"
  vpc_id      = aws_vpc.inspection.id

  health_check {
    port     = 80
    protocol = "HTTP"
  }

  tags = {
    Name     = "inspection-geneve-6081"
    Workload = "inspection"
  }
}

resource "aws_lb_listener" "inspection" {
  load_balancer_arn = aws_lb.inspection.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.inspection.arn
  }
}

resource "aws_lb_target_group_attachment" "appliance_1" {
  target_group_arn = aws_lb_target_group.inspection.arn
  target_id        = aws_instance.appliance_1.id
  port             = 6081
}
