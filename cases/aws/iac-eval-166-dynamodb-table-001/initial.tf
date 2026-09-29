# Pre-existing: the delivery service's rate card store, as it stands before anyone asks for it
# to be loaded. `delivery-rate-card` is the live store the pricing path reads — keyed on
# `RateKey`, on provisioned throughput, carrying the record every resource in this account
# carries: the service that owns it and the team accountable for it.
#
# Nothing here satisfies the task. The store is still standing at the throughput it was
# prototyped on, read 2 / write 2 rather than read 10 / write 10, and it is empty: not one of
# the three rate rows the task seeds is in it, so the pricing path has nothing to read. The
# store itself is what the task acts on; it is never stood up fresh.

resource "aws_dynamodb_table" "rate_card" {
  name           = "delivery-rate-card"
  billing_mode   = "PROVISIONED"
  read_capacity  = 2
  write_capacity = 2
  hash_key       = "RateKey"

  attribute {
    name = "RateKey"
    type = "S"
  }

  tags = {
    Service = "delivery"
    Owner   = "delivery-team"
  }
}
