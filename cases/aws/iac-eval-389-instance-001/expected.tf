# IaC-Eval row 389, the reference output rewritten against the pre-existing orders network
# (provider/terraform blocks dropped, the registry VPC module unrolled into the VPC and the
# two edge subnets that already exist, the AMI lookup inlined onto an image the sandbox can
# actually resolve, the security groups written out in full).
#
# The clean witness of the main intent with nobody else acting: the orders VPC gains an
# internet gateway and a default route for its two edge subnets, an internet-facing
# application load balancer named orders-alb spans those subnets behind a group of its own
# that admits HTTP, the pre-existing orders-app-sg group is opened to that group and placed on
# the pre-existing server, and the load balancer's port-80 listener forwards by default to a
# target group in the VPC holding orders-app-1.

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
  ami                    = data.aws_ami.al2023.id
  instance_type          = "t2.micro"
  subnet_id              = aws_subnet.edge_a.id
  vpc_security_group_ids = [aws_security_group.app.id]

  tags = {
    Name     = "orders-app-1"
    Workload = "orders"
  }
}

resource "aws_internet_gateway" "orders" {
  vpc_id = aws_vpc.orders.id

  tags = {
    Name     = "orders-igw"
    Workload = "orders"
  }
}

resource "aws_route_table" "edge" {
  vpc_id = aws_vpc.orders.id

  tags = {
    Name     = "orders-alb-rt"
    Workload = "orders"
  }
}

resource "aws_route" "edge_default" {
  route_table_id         = aws_route_table.edge.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.orders.id
}

resource "aws_route_table_association" "edge_a" {
  subnet_id      = aws_subnet.edge_a.id
  route_table_id = aws_route_table.edge.id
}

resource "aws_route_table_association" "edge_b" {
  subnet_id      = aws_subnet.edge_b.id
  route_table_id = aws_route_table.edge.id
}

resource "aws_security_group" "lb" {
  name        = "orders-alb-sg"
  description = "orders load balancer"
  vpc_id      = aws_vpc.orders.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name     = "orders-alb-sg"
    Workload = "orders"
  }
}

resource "aws_security_group" "app" {
  name        = "orders-app-sg"
  description = "orders application server"
  vpc_id      = aws_vpc.orders.id

  ingress {
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.lb.id]
  }

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

resource "aws_lb" "orders" {
  name               = "orders-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.lb.id]
  subnets            = [aws_subnet.edge_a.id, aws_subnet.edge_b.id]

  tags = {
    Name     = "orders-alb"
    Workload = "orders"
  }
}

resource "aws_lb_target_group" "app" {
  name        = "orders-app-tg"
  port        = 80
  protocol    = "HTTP"
  target_type = "instance"
  vpc_id      = aws_vpc.orders.id

  tags = {
    Workload = "orders"
  }
}

resource "aws_lb_target_group_attachment" "app" {
  target_group_arn = aws_lb_target_group.app.arn
  target_id        = aws_instance.app.id
  port             = 80
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.orders.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }
}
