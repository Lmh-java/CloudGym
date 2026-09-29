resource "aws_vpc" "dependency" {
  cidr_block = "10.245.0.0/16"
}

resource "aws_default_network_acl" "capability" {
  default_network_acl_id = aws_vpc.dependency.default_network_acl_id

  ingress {
    protocol   = "-1"
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  egress {
    protocol   = "-1"
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  tags = {
    Name = "cloudgym-capability"
  }
}
