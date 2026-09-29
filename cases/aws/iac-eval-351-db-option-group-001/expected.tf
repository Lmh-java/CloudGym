# IaC-Eval reference output for row 351 (provider/terraform blocks dropped; the two external
# inputs the reference quoted as foreign ARNs — the audit writer identity and the evidence
# store — inlined as the account's own pre-existing resources, so the option settings are
# references rather than literals; the identity's write permission on the store, which the
# prompt never mentions, is the task's plumbing).
#
# This is the clean witness of the task with nobody else acting: the evidence is booked on the
# store and the identity the account kept in service at S0, at the root of that store, and the
# option group carries the reference's own marking.

data "aws_caller_identity" "current" {}

resource "aws_s3_bucket" "evidence_store" {
  bucket_prefix = "sqlaudit-${data.aws_caller_identity.current.account_id}-"
  force_destroy = true

  tags = {
    Evidence = "sqlserver-audit"
    Workload = "payments"
  }
}

data "aws_iam_policy_document" "audit_writer_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["rds.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "audit_writer" {
  name               = "sqlserver-audit-writer"
  description        = "Writes SQL Server audit evidence to the account's evidence stores"
  assume_role_policy = data.aws_iam_policy_document.audit_writer_assume.json

  tags = {
    Writes   = "sqlserver-audit"
    Workload = "all"
  }
}

resource "aws_iam_role_policy" "audit_writer" {
  name = "sqlserver-audit-writer"
  role = aws_iam_role.audit_writer.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:ListBucket", "s3:GetBucketLocation"]
        Resource = aws_s3_bucket.evidence_store.arn
      },
      {
        Effect   = "Allow"
        Action   = ["s3:PutObject", "s3:GetObject", "s3:ListMultipartUploadParts", "s3:AbortMultipartUpload"]
        Resource = "${aws_s3_bucket.evidence_store.arn}/*"
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
      value = aws_iam_role.audit_writer.arn
    }
    option_settings {
      name  = "S3_BUCKET_ARN"
      value = aws_s3_bucket.evidence_store.arn
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
