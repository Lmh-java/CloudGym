data "aws_availability_zones" "dependency" {
  state = "available"
}

resource "aws_vpc" "dependency" {
  cidr_block = "10.240.0.0/16"
}

resource "aws_subnet" "dependency" {
  count             = 2
  vpc_id            = aws_vpc.dependency.id
  cidr_block        = cidrsubnet(aws_vpc.dependency.cidr_block, 8, count.index)
  availability_zone = data.aws_availability_zones.dependency.names[count.index]
}

resource "aws_security_group" "dependency" {
  name_prefix = "cloudgym-capability-"
  description = "cloudgym extractor capability fixture"
  vpc_id      = aws_vpc.dependency.id
}

resource "aws_lb" "dependency" {
  name_prefix        = "cwcap-"
  internal           = true
  load_balancer_type = "application"
  security_groups    = [aws_security_group.dependency.id]
  subnets            = aws_subnet.dependency[*].id
}

resource "aws_lb_target_group" "dependency" {
  name_prefix = "cwcap-"
  port        = 80
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = aws_vpc.dependency.id
}

resource "aws_lb_listener" "capability" {
  load_balancer_arn = aws_lb.dependency.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.dependency.arn
  }
}
