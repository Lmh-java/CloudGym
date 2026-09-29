# Pre-existing: the shared platform network, the only network the account has cut out of
# its address plan so far. The plan and the allocation the platform core holds are recorded
# on the VPC itself, which is how this account keeps its allocations: the 10.0.0.0/8 plan,
# with 10.0.0.0/16 recorded against the platform core.
#
# Nothing else is allocated or reserved at S0: no second VPC of the account's plan exists,
# no further range is recorded, no internet gateway of the account's own is present, and
# there is no VPC tagged Name=vpc and no gateway tagged Name=ig anywhere in the region.

resource "aws_vpc" "platform" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name                       = "platform-vpc"
    "address-plan"             = "10.0.0.0/8"
    "allocation:platform-core" = "10.0.0.0/16"
  }
}
