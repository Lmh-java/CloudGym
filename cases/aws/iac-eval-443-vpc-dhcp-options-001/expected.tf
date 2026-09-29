# IaC-Eval reference output for row 443 (provider/terraform blocks dropped; the reference's
# hard-coded `vpc-0c33dc8cd64f408c4` resolved to the VPC that pre-exists in initial.tf).
#
# The clean witness of the task with nobody else acting on the account: one new DHCP option set
# handing out Google's public resolvers, marked `pike = permissions`, with the pike application's
# network resolving through it. This file is never applied.

resource "aws_vpc" "pike" {
  cidr_block           = "10.42.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name     = "pike"
    Workload = "pike"
  }
}

resource "aws_vpc_dhcp_options" "pike" {
  domain_name_servers = ["8.8.8.8", "8.8.4.4"]

  tags = {
    pike = "permissions"
  }
}

resource "aws_vpc_dhcp_options_association" "pike" {
  dhcp_options_id = aws_vpc_dhcp_options.pike.id
  vpc_id          = aws_vpc.pike.id
}
