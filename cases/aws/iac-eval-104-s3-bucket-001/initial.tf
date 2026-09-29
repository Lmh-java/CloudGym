# Pre-existing: the orders application's export store, the only bucket the account keeps
# for that workload today. It carries the account's attribution record the way every store
# here does, and nothing else: no bucket policy, so no address is denied anything at S0,
# and no chargeback or classification record on it either.
#
# `bucket_prefix` instead of the reference's fixed `bucket` name: S3 bucket names are
# global and this case is deployed many times, in several accounts at once. The account id
# keeps the arms apart; 15 + 12 is inside the 37-character prefix limit. (`my_bucket` and
# `test_bucket` are not legal S3 bucket names in any case.)

data "aws_caller_identity" "current" {}

resource "aws_s3_bucket" "orders_exports" {
  bucket_prefix = "orders-exports-${data.aws_caller_identity.current.account_id}"
  force_destroy = true

  tags = {
    "data-owner" = "orders-team"
  }
}
