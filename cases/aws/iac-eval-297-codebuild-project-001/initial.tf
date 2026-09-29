# Pre-existing: the S3 storage this account keeps for what its builds write out. Two stores
# stand side by side — the one the account keeps in service for build output
# (`student-build-output-…`, marked `Status = "current"`) and the one staged for the term ahead
# (`student-build-output-2026-…`, marked `Status = "staged"`), which takes nothing yet. Both
# carry the account's build-output markings, so "the store the account keeps in service for
# build output" is answered by a marking rather than by being the only store of that name.
#
# Nothing here satisfies the task and nothing carries a norm of its own: at S0 the account holds
# no CodeBuild project, no identity trusted by codebuild.amazonaws.com, no store kept for a
# single workload and exactly one store marked as the one in service.

resource "aws_s3_bucket" "build_output" {
  bucket_prefix = "student-build-output-"
  force_destroy = true

  tags = {
    Store  = "build-output"
    Scope  = "account-shared"
    Status = "current"
  }
}

resource "aws_s3_bucket" "build_output_next" {
  bucket_prefix = "student-build-output-2026-"
  force_destroy = true

  tags = {
    Store  = "build-output"
    Scope  = "account-shared"
    Status = "staged"
  }
}
