# Pre-existing: the CS department's autograding setup as it stands before anyone asks for the
# CS110 one — the S3 store the department keeps for what its autograders write out, the
# autograder the department already runs (`cs210-autograder`) and the identity that build runs
# as. The existing build is what the account's descriptions denote today: it fixes the GitHub
# organisation the department's autograders build from, the environment they run in, and the way
# a graded result is written out (an S3 artifact named `results.zip`).
#
# Neither is the only one of its kind by construction: both the store and the autograder carry
# `Status = "current"`, so "the store the department keeps" and "the autograder the department
# keeps in service" still have a readable answer once something else answers to the same
# description.
#
# Nothing here satisfies the task: there is no autograder for CS110, no identity this account
# keeps for the CS110 autograder, no second identity trusted by codebuild.amazonaws.com, no
# second store, no second GitHub organisation and no autograder besides this one.

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
