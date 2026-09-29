# IaC-Eval reference output for row 446 (provider/terraform blocks dropped; the reference's
# `concat` of the two resolver lists written out literally; the pre-existing network carries
# the marking it has in initial.tf). The clean witness of the task with nobody else acting on
# the account: one new DHCP option set handing out the Windows domain name, the custom and
# public resolvers and the NetBIOS name server, and the application network associated with
# it. This file is never applied.

resource "aws_vpc" "default" {
  cidr_block = "192.168.0.0/16"

  tags = {
    Name     = "windomain-vpc"
    Workload = "windomain"
  }
}

resource "aws_vpc_dhcp_options" "default" {
  domain_name          = "windomain.local"
  domain_name_servers  = ["192.168.56.102", "8.8.8.8"]
  netbios_name_servers = ["192.168.56.102"]
}

resource "aws_vpc_dhcp_options_association" "default" {
  vpc_id          = aws_vpc.default.id
  dhcp_options_id = aws_vpc_dhcp_options.default.id
}
