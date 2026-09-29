# Pre-existing: the one store this account keeps for the inventory reports its buckets
# produce. `Store` is the account's marking for what a shared store keeps and `Owner` says
# whose it is — the store is named for being shared, not for what it keeps, so its marking is
# what tells it apart from every other store in the account. Reports from every workload land
# in it; the workload store the task is about does not exist yet.
#
# `bucket_prefix` instead of the reference's fixed `bucket` name: S3 bucket names are global
# and this case is deployed many times, in several accounts at once. The account id keeps the
# arms apart; 14 + 12 + 1 is inside the 37-character prefix limit. (`mybucket` and
# `my-tf-inventory-bucket` are names no account can take twice.)
#
# Nothing of the task exists yet: at S0 the account holds no store under the workload's name,
# no bucket carries an inventory configuration of any kind, the reports store has no bucket
# policy at all, and it records no allocation of the space inside it — so nothing here
# satisfies the task or already carries a norm.

data "aws_caller_identity" "current" {}

resource "aws_s3_bucket" "inventory_reports" {
  bucket_prefix = "reports-store-${data.aws_caller_identity.current.account_id}-"
  force_destroy = true

  tags = {
    Store = "inventory-reports"
    Owner = "platform-team"
  }
}
