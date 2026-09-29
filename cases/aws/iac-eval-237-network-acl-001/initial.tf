# Pre-existing: the application network 10.0.0.0/16 and the one segment already carved out of
# it, `app-shared` (10.0.0.0/24). Both carry the application's attribution, so what a resource
# in this network is charged to can be read off its surroundings.
#
# Nothing controls traffic for this network yet: no network ACL of its own exists at S0, so the
# shared segment sits on the VPC's default ACL, and 10.0.1.0/24 is still unallocated.

resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"

  tags = {
    Name       = "app-vpc"
    Owner      = "storefront-team"
    CostCenter = "APP-2718"
  }
}

resource "aws_subnet" "shared" {
  vpc_id     = aws_vpc.main.id
  cidr_block = "10.0.0.0/24"

  tags = {
    Name       = "app-shared"
    Owner      = "storefront-team"
    CostCenter = "APP-2718"
  }
}
