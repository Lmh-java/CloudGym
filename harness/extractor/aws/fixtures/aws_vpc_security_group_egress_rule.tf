resource "aws_vpc" "dependency" {
  cidr_block = "10.248.0.0/16"
}

resource "aws_security_group" "capability" {
  name_prefix = "cloudgym-capability-"
  description = "cloudgym extractor capability fixture"
  vpc_id      = aws_vpc.dependency.id
}

resource "aws_vpc_security_group_egress_rule" "capability" {
  security_group_id = aws_security_group.capability.id
  cidr_ipv4         = "10.248.0.0/16"
  from_port         = 53
  to_port           = 53
  ip_protocol       = "udp"
  description       = "cloudgym capability egress"
}
