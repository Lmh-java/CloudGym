# Pre-existing: the platform team's source-less smoke build `platform-smoke-build` and the
# role it runs as. It is the account's one CodeBuild project at S0 and shows how a build is
# configured here (curated image `aws/codebuild/standard:6.0`, the default build timeout,
# no environment variables of its own).
#
# Nothing here satisfies the task: the application has no project and no build identity of
# its own at S0 — the smoke build is the platform team's, carries no environment variable,
# and no role besides the smoke runner trusts codebuild.amazonaws.com.

resource "aws_iam_role" "platform_smoke" {
  name = "platform-smoke-runner"

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

resource "aws_codebuild_project" "platform_smoke" {
  name         = "platform-smoke-build"
  description  = "platform smoke build"
  service_role = aws_iam_role.platform_smoke.arn

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
    buildspec = "version: 0.2\nphases:\n  build:\n    commands:\n      - echo smoke\n"
  }
}
