# IaC-Eval reference output for row 294 (provider/terraform blocks and the foreign assume_role
# dropped). The results store pre-exists exactly as in initial.tf — the reference's own
# `artifact-bucket-` prefix is kept so concurrently deployed trials never collide — and the
# autograder build writes into the store that is already there instead of standing up one of
# its own. The project runs as an identity created for it; the grant that lets the build write
# its results into the store is the plumbing the prompt never mentions, so it stands in for the
# reference's `ec2:Describe*` example policy, which grants the build nothing it needs.
#
# This is the witness of the main intent with nobody else acting: every description in the task
# picks out exactly one thing, so the results land at the root of the store, the build runs in
# an environment of the author's choosing, and the obvious name for the build's identity is
# free to take. Never applied.

resource "aws_s3_bucket" "artifact_bucket" {
  bucket_prefix = "artifact-bucket-"
  force_destroy = true

  tags = {
    Store = "autograder-results"
  }
}

# --- the task: an identity for the build, its grant, and the project itself -----------------

data "aws_iam_policy_document" "autograder_build_policy_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["codebuild.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "autograder_build_role" {
  name               = "autograder-build-role"
  assume_role_policy = data.aws_iam_policy_document.autograder_build_policy_assume.json
}

data "aws_iam_policy_document" "autograder_build_policy" {
  statement {
    effect = "Allow"

    actions = [
      "s3:PutObject",
      "s3:GetObject",
      "s3:GetBucketAcl",
      "s3:GetBucketLocation",
    ]

    resources = [
      aws_s3_bucket.artifact_bucket.arn,
      "${aws_s3_bucket.artifact_bucket.arn}/*",
    ]
  }
}

resource "aws_iam_policy" "autograder_build_policy" {
  name        = "autograder-build-results"
  description = "Lets the autograder build write its results into the results store"

  policy = data.aws_iam_policy_document.autograder_build_policy.json
}

resource "aws_iam_role_policy_attachment" "autograder_build_policy_attach" {
  role       = aws_iam_role.autograder_build_role.name
  policy_arn = aws_iam_policy.autograder_build_policy.arn
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
    git_clone_depth = 1
    location        = "https://github.com/example-cs-class/autograder-submissions.git"
  }
}
