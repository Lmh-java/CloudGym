# IaC-Eval row 391, reference output rewritten against the pre-existing network
# (provider/terraform blocks dropped, the VPC module unrolled into the two segments that
# already exist, the listener kept on TCP as a network load balancer requires, and the
# scheme made internal — the storefront's front tier is reached from inside the account,
# and the VPC has no internet gateway. The reference's two security groups collapse to
# the one a network load balancer actually needs: an NLB forwards to its targets without
# a security group of its own, so admitting the traffic is the server's job).
#
# The clean witness of the main intent with nobody else acting: one web server in the
# storefront's network and an internal network load balancer across the segments marked
# as the storefront's front tier — at S0 exactly the two below — listening on TCP 80 and
# forwarding to a target group holding the storefront's web servers, which with nobody
# else acting is the one server the agent launched.

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

resource "aws_vpc" "shop" {
  cidr_block           = "10.40.0.0/16"
  enable_dns_hostnames = true

  tags = {
    Name     = "shop-vpc"
    Workload = "storefront"
  }
}

resource "aws_subnet" "front_a" {
  vpc_id            = aws_vpc.shop.id
  cidr_block        = "10.40.1.0/24"
  availability_zone = data.aws_availability_zones.available.names[0]

  tags = {
    Name     = "shop-front-a"
    Segment  = "front"
    Workload = "storefront"
  }
}

resource "aws_subnet" "front_b" {
  vpc_id            = aws_vpc.shop.id
  cidr_block        = "10.40.2.0/24"
  availability_zone = data.aws_availability_zones.available.names[1]

  tags = {
    Name     = "shop-front-b"
    Segment  = "front"
    Workload = "storefront"
  }
}

resource "aws_security_group" "web" {
  name        = "shop-web"
  description = "Allow HTTP to the storefront web tier from inside shop-vpc"
  vpc_id      = aws_vpc.shop.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.shop.cidr_block]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name     = "shop-web"
    Workload = "storefront"
  }
}

resource "aws_instance" "web" {
  ami                    = data.aws_ami.al2023.id
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.front_a.id
  vpc_security_group_ids = [aws_security_group.web.id]

  tags = {
    Name     = "shop-web-1"
    Workload = "storefront"
    Role     = "web"
  }
}

resource "aws_lb" "shop" {
  name               = "shop-nlb"
  internal           = true
  load_balancer_type = "network"
  subnets            = [aws_subnet.front_a.id, aws_subnet.front_b.id]

  tags = {
    Name     = "shop-nlb"
    Workload = "storefront"
  }
}

resource "aws_lb_target_group" "shop" {
  name        = "shop-web-tcp-80"
  port        = 80
  protocol    = "TCP"
  target_type = "instance"
  vpc_id      = aws_vpc.shop.id

  tags = {
    Name     = "shop-web-tcp-80"
    Workload = "storefront"
  }
}

resource "aws_lb_listener" "shop" {
  load_balancer_arn = aws_lb.shop.arn
  port              = "80"
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.shop.arn
  }
}

resource "aws_lb_target_group_attachment" "web" {
  target_group_arn = aws_lb_target_group.shop.arn
  target_id        = aws_instance.web.id
  port             = 80
}
