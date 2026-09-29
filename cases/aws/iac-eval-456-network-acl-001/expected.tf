# IaC-Eval reference output for row 456 (provider/terraform blocks dropped), on top of the
# pre-existing shared-services network from initial.tf. The witness of the main intent alone:
# a new VPC 10.0.0.0/16 and its own network ACL allowing TCP 80 in from 10.3.0.0/18 and TCP 443
# out to 10.3.0.0/18. It is never applied, and it is not the resolved state after other
# principals act.

resource "aws_vpc" "shared_services" {
  cidr_block = "10.3.0.0/16"

  tags = {
    Name  = "shared-services"
    Owner = "platform-team"
  }
}

resource "aws_subnet" "partner_gateway" {
  vpc_id     = aws_vpc.shared_services.id
  cidr_block = "10.3.0.0/20"

  tags = {
    Name  = "partner-gateway"
    Owner = "platform-team"
  }
}

resource "aws_vpc" "example" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_network_acl" "example" {
  vpc_id = aws_vpc.example.id

  egress {
    protocol   = "tcp"
    rule_no    = 200
    action     = "allow"
    cidr_block = "10.3.0.0/18"
    from_port  = 443
    to_port    = 443
  }

  ingress {
    protocol   = "tcp"
    rule_no    = 100
    action     = "allow"
    cidr_block = "10.3.0.0/18"
    from_port  = 80
    to_port    = 80
  }
}
