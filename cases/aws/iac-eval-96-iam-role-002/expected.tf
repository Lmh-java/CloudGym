# IaC-Eval reference output for row 96 (provider block dropped), on top of the account's
# pre-existing EKS platform identity from initial.tf. This is the witness of the main intent
# with nobody else acting: the account's cluster identity stays exactly as it was, and the new
# role `eks-fargate-profile-example` is stood up under its own name, trusted by the Fargate pod
# service, carrying the AWS managed pod execution policy the request names.

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

resource "aws_iam_role_policy_attachment" "example-AmazonEKSFargatePodExecutionRolePolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSFargatePodExecutionRolePolicy"
  role       = aws_iam_role.example.name
}
