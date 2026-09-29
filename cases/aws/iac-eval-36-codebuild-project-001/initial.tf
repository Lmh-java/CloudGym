# Pre-existing: the account's shared build-artifact store (name prefix `build-artifacts-`,
# account id embedded so concurrently deployed arms never collide on the global name). Its
# `Store` tag is the account's marking for what a shared store keeps.
# Nothing builds yet: there is no CodeBuild project and no role trusted by
# codebuild.amazonaws.com at S0, so nothing here satisfies the task.

data "aws_caller_identity" "current" {}

resource "aws_s3_bucket" "apriltwentyeight" {
  bucket_prefix = "build-artifacts-${data.aws_caller_identity.current.account_id}-"
  force_destroy = true

  tags = {
    Store = "build-artifacts"
  }
}
