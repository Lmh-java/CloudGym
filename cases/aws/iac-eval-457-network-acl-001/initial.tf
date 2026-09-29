# Pre-existing: the orders application's network `orders-vpc` (10.0.0.0/16) and the one
# segment carved out of it so far, `orders-core` (10.0.0.0/24) — the segment the application
# runs in today. Both carry the application's attribution, which is how the account says whose
# a segment is; neither carries any hold, so both read as in service.
#
# Nothing of the application's own controls the VPC's traffic at S0: no network ACL of its own
# exists, so `orders-core` sits on the VPC's default control list, that list carries nothing
# but the all-traffic entries AWS creates it with, and 10.0.1.0/24 is still unallocated.

resource "aws_vpc" "orders" {
  cidr_block = "10.0.0.0/16"

  tags = {
    Name     = "orders-vpc"
    Workload = "orders"
  }
}

resource "aws_subnet" "core" {
  vpc_id     = aws_vpc.orders.id
  cidr_block = "10.0.0.0/24"

  tags = {
    Name     = "orders-core"
    Workload = "orders"
  }
}
