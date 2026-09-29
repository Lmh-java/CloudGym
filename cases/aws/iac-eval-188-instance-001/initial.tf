# Pre-existing: the ledger platform's shared network, `ledger-vpc`, and nothing inside it.
# The VPC is deliberately tight — a /22, four /24s' worth of addresses — and every workload
# in the account is cut a slice of it, so the space is contested rather than abundant. At S0
# it holds no subnet of its own and runs no instance, and its tags carry the attribution
# every resource placed in it is expected to inherit.

resource "aws_vpc" "ledger" {
  cidr_block           = "10.60.0.0/22"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name       = "ledger-vpc"
    App        = "ledger"
    CostCenter = "LEDGER-4471"
  }
}
