# IaC-Eval reference output for row 33 (provider/terraform blocks and the foreign assume_role
# dropped). The account's example build project and the role it runs as pre-exist exactly as
# in initial.tf; the new project takes its GITHUB source from that example — the witness of
# the main intent with nobody else acting, so the location is the one the example shows at S0
# — and runs as a role created for it. The permission to write the build's logs is the
# plumbing the prompt never mentions.

data "aws_iam_policy_document" "example_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["codebuild.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "platform_example_build" {
  name               = "platform-example-build-role"
  assume_role_policy = data.aws_iam_policy_document.example_assume_role.json
}

resource "aws_codebuild_project" "platform_example_build" {
  name         = "platform-example-build"
  description  = "the account's example build project"
  service_role = aws_iam_role.platform_example_build.arn

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
    location        = "https://github.com/acme-platform/build-example.git"
    git_clone_depth = 1
  }

  tags = {
    Example = "build-project"
    Status  = "current"
    Owner   = "platform"
  }
}

data "aws_iam_policy_document" "assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["codebuild.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "test_role" {
  name               = "test_role"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json
}

resource "aws_iam_policy" "test_project_build_logs" {
  name = "test-project-build-logs"

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
        Resource = "arn:aws:logs:*:*:log-group:/aws/codebuild/test-project*"
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "test_project_build_logs" {
  role       = aws_iam_role.test_role.name
  policy_arn = aws_iam_policy.test_project_build_logs.arn
}

resource "aws_codebuild_project" "example" {
  name         = "test-project"
  service_role = aws_iam_role.test_role.arn

  artifacts {
    type = "NO_ARTIFACTS"
  }

  environment {
    compute_type = "BUILD_GENERAL1_SMALL"
    image        = "aws/codebuild/standard:7.0"
    type         = "LINUX_CONTAINER"
  }

  # The example GITHUB source: the location the account's example build project shows.
  source {
    type            = "GITHUB"
    location        = "https://github.com/acme-platform/build-example.git"
    git_clone_depth = 1
  }
}
