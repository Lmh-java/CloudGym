# IaC-Eval reference output for row 301 (provider/terraform blocks and the foreign
# assume_role dropped). The build network and the output store pre-exist exactly as in
# initial.tf — the reference's own `artifact-bucket-` prefix is kept so concurrently
# deployed trials never collide — and the autograder build is placed on a segment of the
# pre-existing VPC and writes into the store that is already there. The reference's
# `ec2:Describe*` example policy is kept and widened to the grants a VPC build actually
# needs (the network interfaces CodeBuild mints in the segment, and the write into the
# output store): that grant is the plumbing the prompt never mentions.
#
# This is the witness of the main intent with nobody else acting on the account: the build
# runs on a segment and a group of its own that give it no way in and no way out, and
# nothing else in the VPC offers it one. Never applied.

resource "aws_vpc" "autograder_vpc" {
  cidr_block = "10.0.0.0/16"

  tags = {
    Name = "autograder-vpc"
  }
}

resource "aws_s3_bucket" "artifact_bucket" {
  bucket_prefix = "artifact-bucket-"
  force_destroy = true

  tags = {
    Store = "autograder-results"
  }
}

# --- the task: an isolated segment, an identity for the build, and the project ------------

# No public addressing: the build's segment hands its workloads no routable address.
resource "aws_subnet" "autograder_vpc_subnet" {
  vpc_id                  = aws_vpc.autograder_vpc.id
  cidr_block              = "10.0.0.0/24"
  map_public_ip_on_launch = false

  tags = {
    Name = "autograder-build"
  }
}

# No ingress and no egress rules at all: students' code can neither be reached nor reach
# anything outside the VPC.
resource "aws_security_group" "autograder_vpc_securitygroup" {
  name        = "autograder-build"
  description = "Autograder builds: no inbound and no outbound access"
  vpc_id      = aws_vpc.autograder_vpc.id

  tags = {
    Name = "autograder-build"
  }
}

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
      "ec2:CreateNetworkInterface",
      "ec2:DeleteNetworkInterface",
      "ec2:DescribeDhcpOptions",
      "ec2:DescribeNetworkInterfaces",
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeSubnets",
      "ec2:DescribeVpcs",
    ]

    resources = ["*"]
  }

  statement {
    effect    = "Allow"
    actions   = ["ec2:CreateNetworkInterfacePermission"]
    resources = ["*"]
  }

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
  name        = "autograder-build-access"
  description = "Lets the autograder build run in the build segment and write its output to the store"

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
    image        = "alpine"
    type         = "LINUX_CONTAINER"
  }

  source {
    type            = "GITHUB"
    git_clone_depth = 1
    location        = "https://github.com/example-cs-class/student-submissions.git"
  }

  vpc_config {
    vpc_id             = aws_vpc.autograder_vpc.id
    subnets            = [aws_subnet.autograder_vpc_subnet.id]
    security_group_ids = [aws_security_group.autograder_vpc_securitygroup.id]
  }
}
