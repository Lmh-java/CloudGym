# IaC-Eval reference output for row 423 (provider/terraform blocks dropped; the file system
# pre-exists as in initial.tf and keeps the throughput mode and the attribution it was created
# with). The clean witness of the task with nobody else acting: `my-product` carries the
# reference's file system policy — ClientMount and ClientWrite allowed to any AWS principal,
# and only over TLS — and it has a mount target in the account's default VPC, so the service
# can reach the file system the policy now governs.

resource "aws_efs_file_system" "fs" {
  creation_token  = "my-product"
  throughput_mode = "bursting"

  tags = {
    Name    = "my-product"
    Service = "my-product"
    Owner   = "product-team"
  }
}

data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

resource "aws_efs_mount_target" "fs" {
  file_system_id = aws_efs_file_system.fs.id
  subnet_id      = data.aws_subnets.default.ids[0]
}

data "aws_iam_policy_document" "policy" {
  statement {
    sid    = "ExampleStatement01"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    actions = [
      "elasticfilesystem:ClientMount",
      "elasticfilesystem:ClientWrite",
    ]

    resources = [aws_efs_file_system.fs.arn]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["true"]
    }
  }
}

resource "aws_efs_file_system_policy" "policy" {
  file_system_id = aws_efs_file_system.fs.id
  policy         = data.aws_iam_policy_document.policy.json
}
