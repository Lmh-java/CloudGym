# Pre-existing: the two things the account already keeps in service for the orders-team
# database audit records — the S3 store the records land in (name prefix `db-audit-`, account
# id embedded so concurrently deployed arms never collide on the global name) and the IAM role
# RDS assumes to deliver them. `Store` is the account's marking for what a shared store keeps,
# `Delivers` the marking for what an identity delivers, and `Owner` says whose records they are.
#
# Nothing of the task exists yet: the account holds no option group of its own at S0 — only the
# default groups RDS keeps per engine version, which carry no options and belong to no workload
# — the delivery identity holds no permission of any kind, and no name in the account's option
# group series is taken. So nothing here satisfies the task or already carries a norm.

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
