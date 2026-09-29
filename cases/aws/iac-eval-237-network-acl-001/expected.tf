# IaC-Eval reference output for row 237 (provider/terraform blocks dropped; the pre-existing
# network and its shared segment carried over from initial.tf verbatim). The reference's network
# ACL is associated with the subnet it controls — that is what "associated network ACLs" asks
# for. This is the clean witness of the task with nobody else acting on the account: the new
# segment carries no attribution and the rules take the reference's own rule numbers, neither of
# which survives contact with the account's conventions.

resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"

  tags = {
    Name       = "app-vpc"
    Owner      = "storefront-team"
    CostCenter = "APP-2718"
  }
}

resource "aws_subnet" "shared" {
  vpc_id     = aws_vpc.main.id
  cidr_block = "10.0.0.0/24"

  tags = {
    Name       = "app-shared"
    Owner      = "storefront-team"
    CostCenter = "APP-2718"
  }
}

resource "aws_subnet" "snet" {
  vpc_id     = aws_vpc.main.id
  cidr_block = "10.0.1.0/24"
}

resource "aws_network_acl" "ntwk_acl" {
  vpc_id     = aws_vpc.main.id
  subnet_ids = [aws_subnet.snet.id]

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
