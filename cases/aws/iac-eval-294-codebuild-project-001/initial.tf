# Pre-existing: the store the CS class keeps its autograder results in — the one bucket in the
# account whose name starts with `artifact-bucket-`, marked as the store those results are kept
# in. The mark is the account's vocabulary for its stores, not a norm of its own.
#
# Nothing builds yet: at S0 the account holds no CodeBuild project at all, no identity trusted
# by codebuild.amazonaws.com, and no grant on the store. The store declares no layout for the
# output written into it, and no second bucket carries its marks, so at S0 every description in
# the task picks out exactly one thing and nothing here satisfies the task.

resource "aws_s3_bucket" "artifact_bucket" {
  bucket_prefix = "artifact-bucket-"
  force_destroy = true

  tags = {
    Store = "autograder-results"
  }
}
