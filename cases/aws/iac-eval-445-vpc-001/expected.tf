# IaC-Eval reference output for row 445 (provider/terraform blocks dropped; the
# `concat` of the two DNS server lists written out; the pre-existing VPC carries
# the Name tag it has in initial.tf). Never applied — the clean witness of the
# main intent with nobody else acting on the account.

resource "aws_vpc" "default" {
  cidr_block = "192.168.0.0/16"

  tags = {
    Name = "windomain-vpc"
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
