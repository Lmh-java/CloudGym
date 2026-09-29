# IaC-Eval reference output for row 350 (provider/terraform blocks dropped; the two external
# inputs the reference quoted as foreign ARNs — the audit delivery role and the audit store —
# inlined as the account's own pre-existing resources, so the option settings are references
# rather than literals; the write permission the delivery role needs on the store, which the
# prompt never mentions, is the task's plumbing).
#
# This is the clean witness of the task with nobody else acting: the account holds no other
# option group of its own, the name `option-group-pike` is free, and the group raised under it
# carries the reference's own options and marking.

data "aws_caller_identity" "current" {}

resource "aws_s3_bucket" "audit_store" {
  bucket_prefix = "db-audit-${data.aws_caller_identity.current.account_id}-"
  force_destroy = true

  tags = {
    Store = "db-audit"
    Owner = "orders-team"
  }
}

data "aws_iam_policy_document" "audit_delivery_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["rds.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "audit_delivery" {
  name               = "db-audit-delivery"
  description        = "Delivers the orders-team database audit records to the account's audit store"
  assume_role_policy = data.aws_iam_policy_document.audit_delivery_assume.json

  tags = {
    Delivers = "db-audit"
    Owner    = "orders-team"
  }
}

resource "aws_iam_role_policy" "audit_delivery" {
  name = "db-audit-delivery"
  role = aws_iam_role.audit_delivery.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:ListBucket", "s3:GetBucketLocation"]
        Resource = aws_s3_bucket.audit_store.arn
      },
      {
        Effect   = "Allow"
        Action   = ["s3:PutObject", "s3:GetObject", "s3:ListMultipartUploadParts", "s3:AbortMultipartUpload"]
        Resource = "${aws_s3_bucket.audit_store.arn}/*"
      },
    ]
  })
}

resource "aws_db_option_group" "example" {
  name                     = "option-group-pike"
  option_group_description = "Terraform Option Group"
  engine_name              = "sqlserver-ee"
  major_engine_version     = "11.00"

  option {
    db_security_group_memberships  = []
    option_name                    = "SQLSERVER_AUDIT"
    port                           = 0
    vpc_security_group_memberships = []

    option_settings {
      name  = "IAM_ROLE_ARN"
      value = aws_iam_role.audit_delivery.arn
    }
    option_settings {
      name  = "S3_BUCKET_ARN"
      value = aws_s3_bucket.audit_store.arn
    }
  }

  option {
    option_name = "TDE"
    port        = 0
  }

  tags = {
    pike = "permissions"
  }
}
