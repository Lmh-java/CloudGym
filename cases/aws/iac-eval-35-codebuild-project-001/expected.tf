# IaC-Eval reference output for row 35 (provider/terraform blocks and the foreign assume_role
# dropped; the buildspec `file("buildspec.yml")` inlined so the case is self-contained).
#
# The platform team's smoke build and its role pre-exist as in initial.tf. The application's
# service role, its permissions policy and the attachment are the plumbing the prompt never
# mentions: a build that writes logs needs them, and the reference role carries none.

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

resource "aws_iam_role" "example3" {
  name = "example3"

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

resource "aws_iam_policy" "example3" {
  name = "example3-codebuild"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:*:*:log-group:/aws/codebuild/*"
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "example3" {
  role       = aws_iam_role.example3.name
  policy_arn = aws_iam_policy.example3.arn
}

resource "aws_codebuild_project" "example3" {
  name         = "DROW3_codebuild"
  description  = "DROW3_codebuild"
  service_role = aws_iam_role.example3.arn

  artifacts {
    type = "NO_ARTIFACTS"
  }

  environment {
    compute_type = "BUILD_GENERAL1_SMALL"
    image        = "aws/codebuild/standard:7.0-24.10.29"
    type         = "LINUX_CONTAINER"

    environment_variable {
      name  = "SOME_KEY1"
      value = "SOME_VALUE1"
    }
  }

  source {
    type      = "NO_SOURCE"
    buildspec = "version: 0.2\nphases:\n  build:\n    commands:\n      - echo \"$SOME_KEY1\"\n"
  }
}
