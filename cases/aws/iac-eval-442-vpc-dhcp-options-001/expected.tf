# IaC-Eval reference output for row 442 (provider/terraform blocks dropped; the reference's
# hard-coded `vpc_id` resolved to the VPC that pre-exists in initial.tf). The clean witness of
# the task with nobody else acting on the account: one new DHCP option set handing out
# Google's public resolvers, marked `pike = permissions`, and the application VPC associated
# with it. This file is never applied.

resource "aws_vpc" "orders" {
  cidr_block           = "10.60.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name     = "orders-app"
    Workload = "orders"
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
  vpc_id          = aws_vpc.orders.id
}
