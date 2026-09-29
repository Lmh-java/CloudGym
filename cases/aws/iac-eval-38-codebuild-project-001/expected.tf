# IaC-Eval reference output for row 38, with nobody else acting on the account: the orders-api
# build project, an identity created for it, the grants that identity needs, a GITHUB primary
# source for the service's own repository and a GITHUB secondary source that pulls the shared
# build tooling — the same tooling repository the payments build already pulls, at whatever
# revision it is pulled at when nothing else moves.
#
# Never applied — the clean witness of the main intent (provider/terraform blocks dropped, the
# build's grants inlined).

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

# --- the task: an identity for the orders-api build, its grants, and the project ----------

resource "aws_iam_role" "orders_build" {
  name = "orders-api-build-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "codebuild.amazonaws.com"
        }
      },
    ]
  })
}

resource "aws_iam_role_policy" "orders_build" {
  name = "orders-api-build"
  role = aws_iam_role.orders_build.id

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
        Resource = "*"
      },
    ]
  })
}

resource "aws_codebuild_project" "orders_build" {
  name         = "orders-api-build"
  description  = "orders-api service build"
  service_role = aws_iam_role.orders_build.arn

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
    location        = "https://github.com/orders-platform/orders-api.git"
    git_clone_depth = 1
  }

  secondary_sources {
    source_identifier = "tooling"
    type              = "GITHUB"
    location          = "https://github.com/orders-platform/build-tooling.git"
    git_clone_depth   = 1
  }
}
