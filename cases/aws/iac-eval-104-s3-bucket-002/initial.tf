# Pre-existing: the one store the platform keeps in this account for workloads to share.
# It is the platform's, not any workload's — `Owner` says whose it is and `Store` says it is
# space the account shares out — and that is all it carries at S0: no bucket policy, so no
# address is refused anything anywhere in the account, no record of how the space inside it is
# handed out, and no record of what the account keeps in it. No store of the orders
# application's partner uploads exists yet, under any name.
#
# `bucket_prefix` instead of the reference's fixed `bucket` name: S3 bucket names are global
# and this case is deployed many times, in several accounts at once. The account id keeps the
# arms apart; 15 + 12 + 1 is inside the 37-character prefix limit. (`my_bucket` and
# `test_bucket` are not legal S3 bucket names in any case.)

data "aws_caller_identity" "current" {}

resource "aws_s3_bucket" "platform_store" {
  bucket_prefix = "platform-store-${data.aws_caller_identity.current.account_id}-"
  force_destroy = true

  tags = {
    Owner = "platform-team"
    Store = "shared-space"
  }
}
