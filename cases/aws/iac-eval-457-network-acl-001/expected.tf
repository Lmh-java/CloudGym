# IaC-Eval reference output for row 457 (provider/terraform blocks dropped; the VPC and the
# segment it already runs carried over from initial.tf verbatim). The reference's network ACL
# is associated with the application's segments — an ACL linked to a VPC but associated with
# nothing controls no traffic, so that association is what "linked to this VPC" comes to — and
# this file is the clean witness of the task with nobody else acting on the account: the
# application's two segments, and the one control list of its own carrying the TCP entries.

resource "aws_vpc" "orders" {
  cidr_block = "10.0.0.0/16"

  tags = {
    Name     = "orders-vpc"
    Workload = "orders"
  }
}

resource "aws_subnet" "core" {
  vpc_id     = aws_vpc.orders.id
  cidr_block = "10.0.0.0/24"

  tags = {
    Name     = "orders-core"
    Workload = "orders"
  }
}

resource "aws_subnet" "app" {
  vpc_id     = aws_vpc.orders.id
  cidr_block = "10.0.1.0/24"

  tags = {
    Name     = "orders-app"
    Workload = "orders"
  }
}

resource "aws_network_acl" "orders" {
  vpc_id     = aws_vpc.orders.id
  subnet_ids = [aws_subnet.core.id, aws_subnet.app.id]

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

  tags = {
    Name     = "orders-control-list"
    Workload = "orders"
  }
}
