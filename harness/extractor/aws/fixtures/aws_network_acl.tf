resource "aws_vpc" "dependency" {
  cidr_block = "10.244.0.0/16"
}

resource "aws_subnet" "dependency" {
  vpc_id     = aws_vpc.dependency.id
  cidr_block = "10.244.1.0/24"
}

resource "aws_network_acl" "capability" {
  vpc_id     = aws_vpc.dependency.id
  subnet_ids = [aws_subnet.dependency.id]

  ingress {
    protocol   = "tcp"
    rule_no    = 100
    action     = "allow"
    cidr_block = "10.0.0.0/8"
    from_port  = 443
    to_port    = 443
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
