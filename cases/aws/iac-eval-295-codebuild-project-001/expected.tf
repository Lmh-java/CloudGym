# IaC-Eval reference output for row 295, with nobody else acting on the account: the CS110
# autograder — a CodeBuild project that builds the class's submissions repository out of the
# organisation the department's autograders build from, in the environment the autograder the
# department keeps in service runs in, and writes the graded result out as an S3 artifact named
# `results.zip` into the store the department keeps in service — plus the identity the account
# keeps for that class's autograder and the grants it holds.
#
# Every one of those descriptions binds to something here only because nobody else acted: with
# one store marked current, one autograder marked current and no identity kept for CS110, the
# organisation is `cs-dept-teaching`, the environment is the one `cs210-autograder` runs in, the
# store is `grader-results-<account>-…` and the identity has to be stood up.
#
# Never applied: the clean witness of the main intent (provider/terraform blocks dropped, the
# build's grants inlined, the pre-existing store and the department's other autograder carried
# over from initial.tf unchanged).

data "aws_caller_identity" "current" {}

resource "aws_s3_bucket" "grader_results" {
  bucket_prefix = "grader-results-${data.aws_caller_identity.current.account_id}-"
  force_destroy = true

  tags = {
    Store  = "grader-results"
    Scope  = "department-shared"
    Status = "current"
  }
}

resource "aws_iam_role" "cs210_autograder" {
  name = "cs210-autograder-role"

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

resource "aws_codebuild_project" "cs210_autograder" {
  name         = "cs210-autograder"
  description  = "CS210 autograder: grades student submissions and stores the result"
  service_role = aws_iam_role.cs210_autograder.arn

  artifacts {
    type      = "S3"
    location  = aws_s3_bucket.grader_results.bucket
    name      = "results.zip"
    packaging = "ZIP"
  }

  environment {
    compute_type = "BUILD_GENERAL1_SMALL"
    image        = "aws/codebuild/standard:7.0"
    type         = "LINUX_CONTAINER"
  }

  source {
    type            = "GITHUB"
    location        = "https://github.com/cs-dept-teaching/cs210-submissions.git"
    git_clone_depth = 1
  }

  tags = {
    Class  = "cs210"
    Status = "current"
  }
}

# --- the task: the CS110 autograder, the identity it runs as, and that identity's grants ----

resource "aws_iam_role" "cs110_autograder" {
  name = "cs110-autograder-role"

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

resource "aws_iam_policy" "cs110_autograder" {
  name        = "cs110-autograder-grants"
  description = "Grants the CS110 autograder needs to grade a submission and store the result"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:GetBucketLocation",
        ]
        Resource = [
          aws_s3_bucket.grader_results.arn,
          "${aws_s3_bucket.grader_results.arn}/*",
        ]
      },
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

resource "aws_iam_role_policy_attachment" "cs110_autograder" {
  role       = aws_iam_role.cs110_autograder.name
  policy_arn = aws_iam_policy.cs110_autograder.arn
}

resource "aws_codebuild_project" "cs110_autograder" {
  name         = "cs110-autograder"
  description  = "CS110 autograder: grades student submissions and stores the result"
  service_role = aws_iam_role.cs110_autograder.arn

  artifacts {
    type      = "S3"
    location  = aws_s3_bucket.grader_results.bucket
    name      = "results.zip"
    packaging = "ZIP"
  }

  environment {
    compute_type = "BUILD_GENERAL1_SMALL"
    image        = "aws/codebuild/standard:7.0"
    type         = "LINUX_CONTAINER"
  }

  source {
    type            = "GITHUB"
    location        = "https://github.com/cs-dept-teaching/cs110-submissions.git"
    git_clone_depth = 1
  }

  tags = {
    Class = "cs110"
  }
}
