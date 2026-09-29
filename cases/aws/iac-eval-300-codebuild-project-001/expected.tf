# IaC-Eval reference output for row 300, with nobody else acting on the account: the
# autograder build project on the class's pre-existing isolated build segment, with a
# security group and a service role of its own, writing its results to a new bucket.
# Never applied — the clean witness of the main intent (provider/terraform blocks
# dropped, the build's grants inlined).

resource "aws_vpc" "autograder_vpc" {
  cidr_block = "10.0.0.0/16"

  tags = {
    Name  = "autograder-vpc"
    class = "cs101"
  }
}

resource "aws_subnet" "autograder_vpc_subnet" {
  vpc_id                  = aws_vpc.autograder_vpc.id
  cidr_block              = "10.0.0.0/24"
  map_public_ip_on_launch = false

  tags = {
    Name  = "autograder-build"
    class = "cs101"
  }
}

# --- the task: a results store, a group and an identity for the build, and the project ---

resource "aws_s3_bucket" "artifact_bucket" {
  bucket_prefix = "autograder-results-"
  force_destroy = true

  tags = {
    Name  = "autograder-results"
    class = "cs101"
  }
}

# No egress rules at all: students' code may not open connections out of the VPC.
resource "aws_security_group" "autograder_vpc_securitygroup" {
  name        = "autograder-build"
  description = "Autograder builds: no outbound access"
  vpc_id      = aws_vpc.autograder_vpc.id

  tags = {
    Name  = "autograder-build"
    class = "cs101"
  }
}

resource "aws_iam_role" "autograder_build_role" {
  name = "autograder-build-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Action    = "sts:AssumeRole"
        Principal = { Service = "codebuild.amazonaws.com" }
      },
    ]
  })

  tags = {
    class = "cs101"
  }
}

resource "aws_iam_policy" "autograder_build_policy" {
  name        = "autograder-build-policy"
  description = "Lets the autograder build attach to the class's build segment and write its results"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ec2:CreateNetworkInterface",
          "ec2:CreateNetworkInterfacePermission",
          "ec2:DeleteNetworkInterface",
          "ec2:DescribeDhcpOptions",
          "ec2:DescribeNetworkInterfaces",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeSubnets",
          "ec2:DescribeVpcs",
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = ["s3:PutObject", "s3:GetObject", "s3:GetBucketLocation", "s3:ListBucket"]
        Resource = [
          aws_s3_bucket.artifact_bucket.arn,
          "${aws_s3_bucket.artifact_bucket.arn}/*",
        ]
      },
    ]
  })
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
    image        = "aws/codebuild/standard:7.0"
    type         = "LINUX_CONTAINER"
  }

  source {
    type            = "GITHUB"
    location        = "https://github.com/cs-class/student-submissions.git"
    git_clone_depth = 1
  }

  # With nobody else re-segmenting the VPC, the class's one build segment is the one
  # the build runs on.
  vpc_config {
    vpc_id             = aws_vpc.autograder_vpc.id
    subnets            = [aws_subnet.autograder_vpc_subnet.id]
    security_group_ids = [aws_security_group.autograder_vpc_securitygroup.id]
  }
}
