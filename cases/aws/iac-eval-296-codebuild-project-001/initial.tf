# Pre-existing: the CS department's own build in this account — the teaching-tools build
# `cs-tooling-build` and the role it runs as. It is the account's one CodeBuild project at S0
# and it is what shows how a build is set up here: a curated build image
# (`aws/codebuild/standard:6.0`), the default build and queued timeouts, no cost-allocation
# marking, no artifacts of its own.
#
# Nothing here satisfies the task: the autograder has no build project, no build identity and
# no results bucket at S0. The tooling build has no source and writes nothing out, the only
# role trusting codebuild.amazonaws.com is the tooling runner, and the account holds no S3
# bucket at all.

resource "aws_iam_role" "cs_tooling_build" {
  name = "cs-tooling-build-runner"

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

resource "aws_codebuild_project" "cs_tooling" {
  name         = "cs-tooling-build"
  description  = "teaching tools build"
  service_role = aws_iam_role.cs_tooling_build.arn

  artifacts {
    type = "NO_ARTIFACTS"
  }

  environment {
    compute_type = "BUILD_GENERAL1_SMALL"
    image        = "aws/codebuild/standard:6.0"
    type         = "LINUX_CONTAINER"
  }

  source {
    type      = "NO_SOURCE"
    buildspec = "version: 0.2\nphases:\n  build:\n    commands:\n      - echo tooling\n"
  }
}
