# Pre-existing: the example build project the account keeps for new workloads to copy, and
# the role it runs as. Its markings say that it is the account's example and that it is the
# one in service; its GITHUB source is the sample repository the example currently builds.
# Nothing of the task exists yet: at S0 the account holds no other CodeBuild project, no
# other role trusted by codebuild.amazonaws.com, no retired example, no second example and
# no pooled build identity — so nothing here satisfies the task or already carries a norm.

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
