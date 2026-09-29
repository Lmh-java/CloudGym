# Pre-existing: the two S3 stores this account keeps for what a build writes out — one for a
# build's artifacts, one for a build's reports. Each declares what it keeps, that it serves the
# whole account rather than a single workload, and that it is the one currently in service; the
# reports store also declares the prefix workloads write under in it.
# Nothing of the task exists yet: at S0 the account holds no CodeBuild project, no role trusted
# by codebuild.amazonaws.com, no second build-artifacts store, no store declared for another
# workload and no pooled build identity — so nothing here satisfies the task or already carries
# a norm.

data "aws_caller_identity" "current" {}

resource "aws_s3_bucket" "build_artifacts" {
  bucket_prefix = "build-artifacts-${data.aws_caller_identity.current.account_id}-"
  force_destroy = true

  tags = {
    Store  = "build-artifacts"
    Scope  = "account-shared"
    Status = "current"
  }
}

resource "aws_s3_bucket" "build_reports" {
  bucket_prefix = "build-reports-${data.aws_caller_identity.current.account_id}-"
  force_destroy = true

  tags = {
    Store  = "build-reports"
    Scope  = "account-shared"
    Status = "current"
    Prefix = "reports"
  }
}
