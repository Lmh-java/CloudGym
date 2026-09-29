# IaC-Eval reference output for row 36 (provider/terraform blocks and the foreign
# assume_role dropped). The artifact bucket pre-exists as in initial.tf; its fixed global
# name `apriltwentyeight` is replaced by the account-scoped prefix so trials never collide.

data "aws_caller_identity" "current" {}

resource "aws_iam_role" "example4" {
  name = "example4"

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

resource "aws_s3_bucket" "apriltwentyeight" {
  bucket_prefix = "build-artifacts-${data.aws_caller_identity.current.account_id}-"
  force_destroy = true

  tags = {
    Store = "build-artifacts"
  }
}

resource "aws_codebuild_project" "example4" {
  name          = "Row4CodeBuild"
  description   = "Row4CodeBuild"
  build_timeout = 5
  service_role  = aws_iam_role.example4.arn

  artifacts {
    type      = "S3"
    location  = aws_s3_bucket.apriltwentyeight.bucket
    name      = "results.zip"
    path      = "/"
    packaging = "ZIP"
  }

  cache {
    type  = "LOCAL"
    modes = ["LOCAL_DOCKER_LAYER_CACHE", "LOCAL_SOURCE_CACHE"]
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
}
