# Pre-existing: the two things the account already keeps in service for the orders-team
# database audit records — the S3 store the records land in (name prefix `db-audit-`, account
# id embedded so concurrently deployed arms never collide on the global name) and the IAM role
# RDS assumes to deliver them. `Store` is the account's marking for what a shared store keeps,
# `Delivers` the marking for what an identity delivers, `Owner` says whose records they are and
# `CostCenter` is the chargeback the workload is booked against.
#
# Nothing of the task exists yet: the account holds no RDS option group of its own at S0, the
# store declares no place under it for anyone to write into, the role holds no inline policy at
# all, and the store and the role are each the only one in the account carrying their marking —
# so nothing here satisfies the task or already carries a norm.

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
    Delivers   = "db-audit"
    Owner      = "orders-team"
    CostCenter = "APP-2210"
  }
}
