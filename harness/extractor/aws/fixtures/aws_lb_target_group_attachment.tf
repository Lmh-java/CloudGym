resource "aws_vpc" "dependency" {
  cidr_block = "10.254.0.0/16"
}

resource "aws_subnet" "dependency" {
  vpc_id     = aws_vpc.dependency.id
  cidr_block = "10.254.1.0/24"
}

resource "aws_lb_target_group" "capability" {
  name_prefix = "cwcap-"
  port        = 80
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = aws_vpc.dependency.id
}

# An IP target inside a VPC subnet needs no running instance; it simply reports unhealthy.
# (ELBv2 rejects an address that is in the VPC CIDR but in no subnet.)
resource "aws_lb_target_group_attachment" "capability" {
  target_group_arn = aws_lb_target_group.capability.arn
  target_id        = "10.254.1.10"
  port             = 80

  depends_on = [aws_subnet.dependency]
}
