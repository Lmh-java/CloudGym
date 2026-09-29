# Pre-existing: the network the pike application already runs in. The prompt refers to it as
# given and asks only for the resolver settings it should hand out. It is the one network in
# the account carrying the free-form workload marking `Workload = pike`; the account's default
# VPC carries no marking at all.
#
# Nothing of the task exists yet. At S0 the account holds no DHCP option set of its own: this
# VPC resolves through the account's default option set (AmazonProvidedDNS), which every
# account has and nobody stood up. No option set in the region hands out Google's resolvers,
# none carries the marking the task asks for, and no second network wears the workload
# marking — so nothing here satisfies the task or already carries a norm.

resource "aws_vpc" "pike" {
  cidr_block           = "10.42.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name     = "pike"
    Workload = "pike"
  }
}
