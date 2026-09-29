# IaC-Eval reference output for row 104 (provider/terraform blocks dropped; the fixed bucket
# names replaced by `bucket_prefix` because S3 bucket names are global and `my_bucket` /
# `test_bucket` are not legal S3 names; the pre-existing platform store copied verbatim from
# initial.tf).
#
# The clean witness of the task with nobody else acting on the account: the platform's shared
# store stands as it did, the orders application's partner uploads get a store of their own
# under the name the task asks for, and the policy document on that store — with a version, an
# identifier and one deny statement — refuses every S3 action on those uploads for requests
# from the partner address.
#
# Which store ends up keeping the partner uploads, how much of that store the refusal covers,
# and how the refused address is stated are not fixed here: with nobody else around the uploads
# get a store of their own, the refusal covers all of it and it names the address the task
# names. What the account's state says about any of the three is read from the account, not
# from this file.

data "aws_caller_identity" "current" {}

resource "aws_s3_bucket" "platform_store" {
  bucket_prefix = "platform-store-${data.aws_caller_identity.current.account_id}-"
  force_destroy = true

  tags = {
    Owner = "platform-team"
    Store = "shared-space"
  }
}

resource "aws_s3_bucket" "orders_intake" {
  bucket_prefix = "orders-intake-${data.aws_caller_identity.current.account_id}-"
  force_destroy = true

  tags = {
    Owner = "orders-team"
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
