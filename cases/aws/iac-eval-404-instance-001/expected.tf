# IaC-Eval row 404, reference output rewritten against the pre-existing storefront network
# (provider/terraform blocks dropped, the community VPC module expanded into the VPC, subnets,
# internet gateway and default route that already exist, and the image data source pinned to an
# image the account can actually launch).
#
# The clean witness of the main intent with nobody else acting: one web server in a public
# subnet of the storefront network with a group of its own that takes HTTP:80 from the load
# balancer, an internet-facing application load balancer across the network's public subnets
# with a group of its own that takes HTTP:80 from anywhere, an HTTP:80 listener whose default
# action forwards to a new instance-target group on HTTP:80 in that VPC, and that web server
# registered as the group's target.

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

resource "aws_vpc" "storefront" {
  cidr_block           = "10.60.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "storefront-vpc"
    App  = "storefront"
  }
}

resource "aws_subnet" "public" {
  count                   = 3
  vpc_id                  = aws_vpc.storefront.id
  cidr_block              = cidrsubnet(aws_vpc.storefront.cidr_block, 8, count.index + 1)
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true

  tags = {
    Name = "storefront-public-${count.index + 1}"
    Tier = "public"
    App  = "storefront"
  }
}

resource "aws_internet_gateway" "storefront" {
  vpc_id = aws_vpc.storefront.id

  tags = {
    Name = "storefront-igw"
    App  = "storefront"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.storefront.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.storefront.id
  }

  tags = {
    Name = "storefront-public-rt"
    App  = "storefront"
  }
}

resource "aws_route_table_association" "public" {
  count          = 3
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_security_group" "edge" {
  name        = "storefront-edge-sg"
  description = "storefront internet-facing load balancer"
  vpc_id      = aws_vpc.storefront.id

  tags = {
    Name = "storefront-edge-sg"
    App  = "storefront"
  }
}

resource "aws_vpc_security_group_ingress_rule" "edge_http" {
  security_group_id = aws_security_group.edge.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 80
  to_port           = 80
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "edge_out" {
  security_group_id = aws_security_group.edge.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

resource "aws_security_group" "web" {
  name        = "storefront-web-sg"
  description = "storefront web server"
  vpc_id      = aws_vpc.storefront.id

  tags = {
    Name = "storefront-web-sg"
    App  = "storefront"
  }
}

resource "aws_vpc_security_group_ingress_rule" "web_http" {
  security_group_id            = aws_security_group.web.id
  referenced_security_group_id = aws_security_group.edge.id
  from_port                    = 80
  to_port                      = 80
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "web_out" {
  security_group_id = aws_security_group.web.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

resource "aws_instance" "web" {
  ami                    = data.aws_ami.al2023.id
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.public[0].id
  vpc_security_group_ids = [aws_security_group.web.id]

  tags = {
    Name = "storefront-web-1"
    App  = "storefront"
  }
}

resource "aws_lb" "storefront" {
  name               = "storefront-edge-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.edge.id]
  subnets            = [for s in aws_subnet.public : s.id]

  tags = {
    Name = "storefront-edge-alb"
    App  = "storefront"
  }
}

resource "aws_lb_target_group" "web" {
  name        = "storefront-web-tg"
  port        = 80
  protocol    = "HTTP"
  target_type = "instance"
  vpc_id      = aws_vpc.storefront.id

  tags = {
    Name = "storefront-web-tg"
    App  = "storefront"
  }
}

resource "aws_lb_target_group_attachment" "web" {
  target_group_arn = aws_lb_target_group.web.arn
  target_id        = aws_instance.web.id
  port             = 80
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.storefront.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.web.arn
  }
}
