# IaC-Eval reference output for row 455 (provider/terraform blocks dropped; the reference's
# literal `default_network_acl_id` replaced by the id of the pre-existing network's own default
# list, which is what that literal stands for), on top of the network carried over from
# initial.tf.
#
# The clean witness of the task with nobody else acting on the account: the two segments the
# task names, carved in `pike-net`, and that network's default control list rewritten to the
# reference's unrestricted pair — all protocols, rule 100, allow, from 0.0.0.0/0 inbound and to
# 0.0.0.0/0 outbound. It is never applied, and it is not the resolved state once other owners
# have entries, marks and allocations of their own in that network.

resource "aws_vpc" "pike" {
  cidr_block = "10.40.0.0/16"

  tags = {
    Name     = "pike-net"
    Workload = "pike"
  }
}

resource "aws_subnet" "pike_app" {
  vpc_id     = aws_vpc.pike.id
  cidr_block = "10.40.1.0/24"

  tags = {
    Name     = "pike-app"
    Workload = "pike"
  }
}

resource "aws_subnet" "pike_batch" {
  vpc_id     = aws_vpc.pike.id
  cidr_block = "10.40.2.0/24"

  tags = {
    Name     = "pike-batch"
    Workload = "pike"
  }
}

resource "aws_default_network_acl" "pike" {
  default_network_acl_id = aws_vpc.pike.default_network_acl_id

  ingress {
    protocol   = -1
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  egress {
    protocol   = -1
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  tags = {
    Name     = "pike-net-default"
    Workload = "pike"
  }
}
