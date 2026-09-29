# Pre-existing: the EKS platform this account already runs. The platform team keeps one
# cluster identity for the control plane, `eks-platform-cluster-role`, and it carries the AWS
# managed cluster policy. That is the whole of the account's EKS identity landscape at S0.
#
# Nothing of the task exists yet: at S0 the account holds no role named
# eks-fargate-profile-example, no role trusted by the Fargate pod service at all, no identity
# any pod runs as, no role carrying a pod execution policy and no customer managed pod
# execution policy — so nothing here satisfies the task, and no other principal's mark is on
# the account.

data "aws_iam_policy_document" "platform_cluster_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["eks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "platform_cluster" {
  name               = "eks-platform-cluster-role"
  description        = "control plane identity of the account's EKS platform"
  assume_role_policy = data.aws_iam_policy_document.platform_cluster_assume_role.json

  tags = {
    Owner     = "platform"
    Component = "eks-control-plane"
  }
}

resource "aws_iam_role_policy_attachment" "platform_cluster" {
  role       = aws_iam_role.platform_cluster.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}
