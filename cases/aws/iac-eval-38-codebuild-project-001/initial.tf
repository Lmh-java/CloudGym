# Pre-existing: the payments-api service's build and the identity it runs as. It is the
# account's one CodeBuild project at S0 and shows how a build is put together here — a GITHUB
# primary source for the service's own repository and a GITHUB secondary source that pulls the
# shared build tooling everything in this account builds with.
#
# Nothing here satisfies the task: the orders-api service has no build project and no build
# identity of its own, the payments build is the payments team's, no role besides the payments
# runner trusts codebuild.amazonaws.com, and no build in the account carries a revision pin, a
# cutover record or an attribution mark of any kind.

resource "aws_iam_role" "payments_build" {
  name = "payments-api-build-role"

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

resource "aws_codebuild_project" "payments_build" {
  name         = "payments-api-build"
  description  = "payments-api service build"
  service_role = aws_iam_role.payments_build.arn

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
    location        = "https://github.com/orders-platform/payments-api.git"
    git_clone_depth = 1
  }

  secondary_sources {
    source_identifier = "tooling"
    type              = "GITHUB"
    location          = "https://github.com/orders-platform/build-tooling.git"
    git_clone_depth   = 1
  }
}
