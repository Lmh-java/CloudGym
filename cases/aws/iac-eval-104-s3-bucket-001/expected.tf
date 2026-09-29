# IaC-Eval reference output for row 104 (provider/terraform blocks dropped; the fixed
# bucket names replaced by `bucket_prefix` because S3 bucket names are global and
# `my_bucket` / `test_bucket` are not legal S3 names).
#
# The clean witness of the main intent with nobody else acting on the account: the export
# store pre-exists as in initial.tf, and the partner intake bucket stands beside it with a
# policy document that denies every S3 action on its objects for the partner address. The
# intake bucket carries the same attribution record the export store carries — that is the
# account's standing convention for a store, not something the utterance asks for.

data "aws_caller_identity" "current" {}

resource "aws_s3_bucket" "orders_exports" {
  bucket_prefix = "orders-exports-${data.aws_caller_identity.current.account_id}"
  force_destroy = true

  tags = {
    "data-owner" = "orders-team"
  }
}

resource "aws_s3_bucket" "orders_intake" {
  bucket_prefix = "orders-intake-${data.aws_caller_identity.current.account_id}"
  force_destroy = true

  tags = {
    "data-owner" = "orders-team"
  }
}

resource "aws_s3_bucket_policy" "orders_intake" {
  bucket = aws_s3_bucket.orders_intake.id

  policy = jsonencode({
    "Version" : "2012-10-17",
    "Id" : "orders-intake-policy",
    "Statement" : [
      {
        "Sid" : "DenyPartnerAddress",
        "Effect" : "Deny",
        "Principal" : "*",
        "Action" : "s3:*",
        "Resource" : "${aws_s3_bucket.orders_intake.arn}/*",
        "Condition" : {
          "IpAddress" : { "aws:SourceIp" : "203.0.113.42/32" }
        }
      }
    ]
  })
}
