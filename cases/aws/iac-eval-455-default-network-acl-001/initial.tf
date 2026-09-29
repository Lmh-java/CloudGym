# Pre-existing: the integration-test network `pike-net` (10.40.0.0/16) and the control list it
# hands a segment by default. The network is empty — no segment is carved in it yet, so
# 10.40.1.0/24 and 10.40.2.0/24 are both unallocated — and the list it hands a segment by
# default is not wide open: the all-traffic entries EC2 writes a new network's default list with
# have been replaced by a pair that admits nothing but TCP inside the network itself, one entry
# inbound and one outbound, at a slot well above anything else on the list.
#
# Nothing of the task holds at S0: no segment of the `pike` workload exists, no entry on that
# list allows any protocol from any source or to any destination, and no entry, mark or
# allocation of another owner's stands anywhere in the network.

resource "aws_vpc" "pike" {
  cidr_block = "10.40.0.0/16"

  tags = {
    Name     = "pike-net"
    Workload = "pike"
  }
}

resource "aws_default_network_acl" "pike" {
  default_network_acl_id = aws_vpc.pike.default_network_acl_id

  ingress {
    protocol   = "tcp"
    rule_no    = 300
    action     = "allow"
    cidr_block = "10.40.0.0/16"
    from_port  = 0
    to_port    = 65535
  }

  egress {
    protocol   = "tcp"
    rule_no    = 300
    action     = "allow"
    cidr_block = "10.40.0.0/16"
    from_port  = 0
    to_port    = 65535
  }

  tags = {
    Name     = "pike-net-default"
    Workload = "pike"
  }
}
