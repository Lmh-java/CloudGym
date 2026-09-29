# IaC-Eval reference output for row 39 (provider/terraform blocks and the foreign assume_role
# dropped). The account's two build stores pre-exist exactly as in initial.tf — the reference's
# two fixed global bucket names are replaced by account-scoped prefixes so concurrently
# deployed trials never collide — and the new project writes into them instead of standing up
# buckets of its own: its artifacts into the shared build-artifacts store, its secondary
# artifact into the shared build-reports store. The project runs as a role created for it; the
# grant that lets the build write into the two stores is the plumbing the prompt never mentions.
#
# This is the witness of the main intent with nobody else acting, so the store the artifacts go
# to is the one in service at S0. Never applied.

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

# --- the task: an identity for the build, its grants, and the project itself ---------------

resource "aws_iam_role" "test_role8" {
  name = "test_role8"

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

resource "aws_iam_policy" "test_project8_build_output" {
  name = "test-project8-build-output"

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
          aws_s3_bucket.build_reports.arn,
          "${aws_s3_bucket.build_reports.arn}/*",
        ]
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "test_project8_build_output" {
  role       = aws_iam_role.test_role8.name
  policy_arn = aws_iam_policy.test_project8_build_output.arn
}

resource "aws_codebuild_project" "example7" {
  name         = "test-project8"
  service_role = aws_iam_role.test_role8.arn

  artifacts {
    location  = aws_s3_bucket.build_artifacts.bucket
    type      = "S3"
    name      = "results.zip"
    path      = "/"
    packaging = "ZIP"
  }

  secondary_artifacts {
    artifact_identifier = "SecondaryArtifact"
    type                = "S3"
    location            = aws_s3_bucket.build_reports.bucket
    name                = "reports.zip"
    packaging           = "ZIP"
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

  secondary_sources {
    source_identifier = "source2"
    type              = "GITHUB"
    location          = "https://github.com/mitchellh/packer.git"
    git_clone_depth   = 1
  }

  secondary_source_version {
    source_identifier = "source2"
    source_version    = "master"
  }
}
