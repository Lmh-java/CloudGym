# Pre-existing: the application VPC whose name resolution the task is about. It is the
# network the orders workload already runs in — the prompt refers to it as given and asks
# only for the resolver settings it should hand out.
#
# Nothing of the task exists yet. At S0 the account holds no DHCP option set of its own: the
# VPC resolves through the account's default option set (AmazonProvidedDNS), which every
# account has and which no one stood up. No option set in the region hands out Google's
# resolvers, none carries the workload marking the task asks for, and the account records
# nothing on this VPC about what it must resolve under — so nothing here satisfies the task
# or already carries a norm.

resource "aws_vpc" "orders" {
  cidr_block           = "10.60.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name     = "orders-app"
    Workload = "orders"
  }
}
