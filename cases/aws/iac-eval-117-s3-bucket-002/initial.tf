# Pre-existing: the S3 store the account keeps in service for the orders-team application's log
# objects (name prefix `app-logs-`, the account id embedded so concurrently deployed arms never
# collide on the global name). `Store` is the account's marking for what a store keeps and
# `Owner` says whose objects are in it.
#
# Nothing of the task exists yet, and no delivery of any kind leaves the store: at S0 the account
# holds no SNS topic at all, the store has no notification configuration, and it carries no mark
# beyond what it keeps and who owns it — so nothing here satisfies the task or already carries a
# norm.

data "aws_caller_identity" "current" {}

resource "aws_s3_bucket" "bucket" {
  bucket_prefix = "app-logs-${data.aws_caller_identity.current.account_id}-"
  force_destroy = true

  tags = {
    Store = "app-logs"
    Owner = "orders-team"
  }
}
