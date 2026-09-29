# Pre-existing: the S3 store this account keeps for what its builds write out, and the one
# build the account runs on its shared build capacity — `billing-api-build` and the identity it
# runs as. The build shows how a build is put together here and, through its own batch
# configuration, what the account currently holds a build on its shared capacity to: it is
# marked `Capacity=account-pool` (it draws on the account's shared build capacity) and
# `Status=current` (it is the one in service).
#
# Nothing here satisfies the task: the account holds no second build project, no second identity
# trusted by codebuild.amazonaws.com, no build marked for a single workload, no build marked out
# of service or naming a successor, and no pooled batch identity.

data "aws_caller_identity" "current" {}

resource "aws_s3_bucket" "build_artifacts" {
  bucket_prefix = "build-artifacts-${data.aws_caller_identity.current.account_id}-"
  force_destroy = true

  tags = {
    Store = "build-artifacts"
    Scope = "account-shared"
  }
}

resource "aws_iam_role" "billing_api_build" {
  name = "billing-api-build-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "codebuild.amazonaws.com"
        }
      },
    ]
  })
}

resource "aws_codebuild_project" "billing_api_build" {
  name         = "billing-api-build"
  description  = "billing-api service build"
  service_role = aws_iam_role.billing_api_build.arn

  artifacts {
    type = "NO_ARTIFACTS"
  }

  environment {
    compute_type = "BUILD_GENERAL1_SMALL"
    image        = "aws/codebuild/standard:7.0"
    type         = "LINUX_CONTAINER"
  }

  source {
    type            = "GITHUB"
    location        = "https://github.com/example-corp/billing-api.git"
    git_clone_depth = 1
  }

  build_batch_config {
    service_role = aws_iam_role.billing_api_build.arn

    restrictions {
      maximum_builds_allowed = 8
    }
  }

  tags = {
    Capacity = "account-pool"
    Status   = "current"
  }
}
