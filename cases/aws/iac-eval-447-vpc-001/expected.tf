# IaC-Eval reference output for row 447 (provider/terraform blocks dropped; the
# pre-existing VPC carries the Name tag it has in initial.tf). Never applied:
# this is the witness of the main intent carried out with nobody else acting on
# the account.

resource "aws_vpc" "default" {
  cidr_block = "192.168.0.0/16"

  tags = {
    Name = "windomain-vpc"
  }
}

resource "aws_vpc_dhcp_options" "default" {
  domain_name          = "windomain.local"
  domain_name_servers  = concat(["192.168.56.102"], ["8.8.8.8"])
  netbios_name_servers = ["192.168.56.102"]
}

resource "aws_vpc_dhcp_options_association" "default" {
  vpc_id          = aws_vpc.default.id
  dhcp_options_id = aws_vpc_dhcp_options.default.id
}
