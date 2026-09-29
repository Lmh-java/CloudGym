resource "aws_vpc" "dependency" {
  cidr_block = "10.247.0.0/16"
}

resource "aws_security_group" "capability" {
  name_prefix = "cloudgym-capability-"
  description = "cloudgym extractor capability fixture"
  vpc_id      = aws_vpc.dependency.id
}

resource "aws_vpc_security_group_ingress_rule" "capability" {
  security_group_id = aws_security_group.capability.id
  cidr_ipv4         = "10.247.0.0/16"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  description       = "cloudgym capability ingress"
}
