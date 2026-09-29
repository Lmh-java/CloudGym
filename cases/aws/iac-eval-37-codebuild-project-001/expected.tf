# IaC-Eval reference output for row 37 (provider/terraform blocks and the foreign
# assume_role dropped). The build-log store pre-exists as in initial.tf; its fixed global
# name `apriltwentynine` is replaced by the account-scoped prefix so trials never collide.
# The witness of the main intent with nobody else acting: the project writes its build logs
# into the store the account keeps for build logs at S0. The permission to write those logs
# is the plumbing the prompt never mentions.

data "aws_caller_identity" "current" {}

resource "aws_iam_role" "example5" {
  name = "example5"

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

resource "aws_s3_bucket" "apriltwentynine" {
  bucket_prefix = "build-logs-${data.aws_caller_identity.current.account_id}-"
  force_destroy = true

  tags = {
    Store = "build-logs"
    Owner = "platform"
  }
}

resource "aws_iam_policy" "example5_build_logs" {
  name = "Row5CodeBuild-build-logs"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
        ]
        Resource = "arn:aws:logs:*:*:log-group:log-group*"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetBucketAcl",
          "s3:GetBucketLocation",
        ]
        Resource = [
          aws_s3_bucket.apriltwentynine.arn,
          "${aws_s3_bucket.apriltwentynine.arn}/*",
        ]
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "example5_build_logs" {
  role       = aws_iam_role.example5.name
  policy_arn = aws_iam_policy.example5_build_logs.arn
}

resource "aws_codebuild_project" "example5" {
  name          = "Row5CodeBuild"
  description   = "Row5CodeBuild"
  build_timeout = 5
  service_role  = aws_iam_role.example5.arn

  artifacts {
    type = "NO_ARTIFACTS"
  }

  environment {
    compute_type                = "BUILD_GENERAL1_SMALL"
    image                       = "aws/codebuild/standard:7.0-24.10.29"
    type                        = "LINUX_CONTAINER"
    image_pull_credentials_type = "CODEBUILD"
  }

  logs_config {
    cloudwatch_logs {
      group_name  = "log-group"
      stream_name = "log-stream"
    }

    s3_logs {
      status   = "ENABLED"
      location = "${aws_s3_bucket.apriltwentynine.id}/build-log"
    }
  }

  source {
    type            = "GITHUB"
    location        = "https://github.com/mitchellh/packer.git"
    git_clone_depth = 1
  }

  source_version = "master"
}
