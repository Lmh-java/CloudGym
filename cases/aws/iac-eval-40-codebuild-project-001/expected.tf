# IaC-Eval reference output for row 40 (provider/terraform blocks and the foreign assume_role
# dropped). The account's build-artifacts store and its one shared-capacity build pre-exist
# exactly as in initial.tf — the reference's fixed global bucket name is replaced by an
# account-scoped prefix so concurrently deployed trials never collide — and the new project
# writes into the store that is already there instead of standing up a bucket of its own. The
# project runs as a role created for it; the grant that lets the build write into the store is
# the plumbing the prompt never mentions.
#
# This is the witness of the main intent with nobody else acting, so the concurrent-build
# allowance the batch configuration carries is the one the account holds its shared-capacity
# builds to at S0 — 8, read off `billing-api-build` — rather than the reference's own literal.
# Never applied.

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

# --- the task: an identity for the build, its grant, and the project itself -----------------

resource "aws_iam_role" "test_role9" {
  name = "test_role9"

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

resource "aws_iam_policy" "test_project9_build_output" {
  name = "test-project9-build-output"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:GetBucketLocation",
          "s3:ListBucket",
        ]
        Resource = [
          aws_s3_bucket.build_artifacts.arn,
          "${aws_s3_bucket.build_artifacts.arn}/*",
        ]
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "test_project9_build_output" {
  role       = aws_iam_role.test_role9.name
  policy_arn = aws_iam_policy.test_project9_build_output.arn
}

resource "aws_codebuild_project" "example9" {
  name         = "test-project9"
  service_role = aws_iam_role.test_role9.arn

  artifacts {
    location  = aws_s3_bucket.build_artifacts.bucket
    name      = "results.zip"
    type      = "S3"
    path      = "/"
    packaging = "ZIP"
  }

  environment {
    compute_type                = "BUILD_GENERAL1_SMALL"
    image                       = "aws/codebuild/standard:7.0-24.10.29"
    type                        = "LINUX_CONTAINER"
    image_pull_credentials_type = "CODEBUILD"
  }

  source {
    type            = "GITHUB"
    location        = "https://github.com/mitchellh/packer.git"
    git_clone_depth = 1
  }

  source_version = "master"

  build_batch_config {
    service_role = aws_iam_role.test_role9.arn

    restrictions {
      maximum_builds_allowed = 8
    }
  }
}
