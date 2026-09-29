# Pre-existing: the Fargate profile role the account already runs, and the pod execution
# policy it carries. Its markings say that it is one of the account's Fargate profile roles
# and that it is the one in service, so it is what the account currently designates when
# something here is called "predefined" for Fargate profiles.
#
# Nothing of the task exists yet: at S0 the account holds no role named
# eks-fargate-profile-example, no second Fargate profile role, no retired or successor
# profile role, no sibling copy, no pooled pod execution identity and no customer managed
# pod execution policy — so nothing here satisfies the task or already carries a norm.

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
