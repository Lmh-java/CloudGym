# IaC-Eval reference output for row 296 (provider/terraform blocks and the foreign assume_role
# dropped). The department's teaching-tools build pre-exists exactly as in initial.tf; the task
# adds the autograder: a results bucket, an identity for the build, the grant that lets the
# build write its results out, and the project itself.
#
# Two departures from the row's reference, both mechanical: the results bucket is named by
# prefix so concurrently deployed trials never collide, and the build's grant is the S3 write
# access the results actually need instead of the row's copy-pasted ec2:Describe* policy. The
# artifacts location is the bucket name, which is what CodeBuild stores there (the row wrote
# the ARN).
#
# This is the witness of the main intent with nobody else acting on the account, so the build
# environment, the timeouts and the layout of the results are the ones the task itself implies.
# Never applied.

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

# --- the task: somewhere to keep the results, an identity for the build, and the project ----

resource "aws_s3_bucket" "artifact_bucket" {
  bucket_prefix = "autograder-artifacts-"
  force_destroy = true
}

resource "aws_iam_role" "autograder_build_role" {
  name = "autograder-build-role"

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

resource "aws_iam_policy" "autograder_build_output" {
  name        = "autograder-build-output"
  description = "Lets the autograder build write its results out"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:GetBucketLocation",
          "s3:ListBucket",
        ]
        Resource = [
          aws_s3_bucket.artifact_bucket.arn,
          "${aws_s3_bucket.artifact_bucket.arn}/*",
        ]
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "autograder_build_output" {
  role       = aws_iam_role.autograder_build_role.name
  policy_arn = aws_iam_policy.autograder_build_output.arn
}

resource "aws_codebuild_project" "autograder_build" {
  name         = "autograder-build"
  service_role = aws_iam_role.autograder_build_role.arn

  artifacts {
    type     = "S3"
    location = aws_s3_bucket.artifact_bucket.bucket
    name     = "results.zip"
  }

  environment {
    compute_type = "BUILD_GENERAL1_SMALL"
    image        = "aws/codebuild/standard:7.0-24.10.29"
    type         = "LINUX_CONTAINER"
  }

  source {
    type            = "GITHUB"
    location        = "https://github.com/cs-class/student-submissions.git"
    git_clone_depth = 1
  }
}
