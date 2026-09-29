resource "aws_vpc" "dependency" {
  cidr_block = "10.249.0.0/16"
}

resource "aws_security_group" "capability" {
  name_prefix = "cloudgym-capability-"
  description = "cloudgym extractor capability fixture"
  vpc_id      = aws_vpc.dependency.id
}

resource "aws_security_group_rule" "capability" {
  type              = "ingress"
  security_group_id = aws_security_group.capability.id
  cidr_blocks       = ["10.249.0.0/16"]
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  description       = "cloudgym capability legacy rule"
}
