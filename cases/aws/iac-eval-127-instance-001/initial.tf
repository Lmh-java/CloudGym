# Pre-existing: the shared application VPC, 10.0.0.0/16, and nothing inside it. The
# account's workloads are allocated address space out of this one VPC, but no range has
# been cut yet: at S0 the VPC holds no subnet of its own and runs no instance.

resource "aws_vpc" "app" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "app-vpc"
    App  = "storefront"
  }
}
