# Pre-existing: the S3 store the account keeps for build logs (name prefix
# `build-logs-`, account id embedded so concurrently deployed arms never collide on the
# global name). Its `Store` tag is the account's marking for what a shared store keeps;
# `Owner` says whose store it is.
# Nothing of the task exists yet: at S0 the account holds no CodeBuild project, no role
# trusted by codebuild.amazonaws.com, no second store marked for build logs, no successor
# store and no shared log sink — so nothing here satisfies the task or already carries a
# norm.

data "aws_caller_identity" "current" {}

resource "aws_s3_bucket" "apriltwentynine" {
  bucket_prefix = "build-logs-${data.aws_caller_identity.current.account_id}-"
  force_destroy = true

  tags = {
    Store = "build-logs"
    Owner = "platform"
  }
}
