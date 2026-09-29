resource "aws_vpc" "dependency" {
  cidr_block = "10.253.0.0/16"
}

resource "aws_lb_target_group" "capability" {
  name_prefix = "cwcap-"
  port        = 80
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = aws_vpc.dependency.id
}
