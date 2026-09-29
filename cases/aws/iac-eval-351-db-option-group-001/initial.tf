# Pre-existing: the two things the account already keeps in service for SQL Server audit
# evidence — the S3 store the `payments` workload's evidence lands in (name prefix `sqlaudit-`,
# account id embedded so concurrently deployed arms never collide on the global name) and the
# IAM identity RDS assumes to write evidence. `Evidence` is the account's marking for what a
# store keeps, `Writes` the marking for what an identity writes, and `Workload` says whose it
# is: the store is kept for `payments`, the writer identity is kept for every workload at S0.
#
# Nothing of the task exists yet: the account holds no RDS option group of its own at S0, the
# store declares no place under it for anyone to write into, the identity holds no inline
# policy at all, and the store and the identity are each the only one in the account carrying
# their marking — so nothing here satisfies the task or already carries a norm.

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
