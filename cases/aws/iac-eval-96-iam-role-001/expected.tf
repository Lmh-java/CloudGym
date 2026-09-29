# IaC-Eval reference output for row 96 (provider block dropped). The account's Fargate
# profile role and the pod execution policy it carries pre-exist exactly as in initial.tf;
# the new role takes its pod execution policy from what that role shows — the witness of the
# main intent with nobody else acting, so the policy is the one the designated role carries
# at S0, the AWS managed Amazon EKS Fargate pod execution policy of the reference.

data "aws_iam_policy_document" "platform_fargate_profile_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["eks-fargate-pods.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "platform_fargate_profile" {
  name               = "platform-fargate-profile-role"
  description        = "the account's EKS Fargate profile role"
  assume_role_policy = data.aws_iam_policy_document.platform_fargate_profile_assume_role.json

  tags = {
    Purpose = "fargate-pod-execution"
    Status  = "current"
    Owner   = "platform"
  }
}

resource "aws_iam_role_policy_attachment" "platform_fargate_profile" {
  role       = aws_iam_role.platform_fargate_profile.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSFargatePodExecutionRolePolicy"
}

resource "aws_iam_role" "example" {
  name = "eks-fargate-profile-example"

  assume_role_policy = jsonencode({
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "eks-fargate-pods.amazonaws.com"
      }
    }]
    Version = "2012-10-17"
  })
}

# The pod execution policy the account has predefined for its Fargate profile roles: the one
# the role it designates carries.
resource "aws_iam_role_policy_attachment" "example-AmazonEKSFargatePodExecutionRolePolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSFargatePodExecutionRolePolicy"
  role       = aws_iam_role.example.name
}
