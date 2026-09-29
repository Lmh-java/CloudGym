# IaC-Eval reference output for row 273 (provider/terraform blocks dropped; the pre-existing
# reports store copied verbatim from initial.tf). The clean witness of the task with nobody
# else around: the workload store the row asks for, its inventory configuration reporting the
# whole store daily, and the delivery of those reports into the store the account already
# keeps for inventory reports.
#
# Two deviations from the row's reference text, both forced by what S3 accepts:
#   * the row names the buckets `mybucket` and `my-tf-inventory-bucket`, placeholders in a
#     global namespace no account can actually take, so both stand under a `bucket_prefix`
#     carrying the account id — the reports store is the one the account already keeps, and
#     the workload store is the `mybucket-` store the task asks for;
#   * the row's reference stops at the inventory configuration. A report is only delivered
#     when the receiving store admits the write, so the delivery grant on the reports store
#     is part of what the task produces; the row never mentions it because it builds both
#     stores from scratch in an empty account.
#
# Where the reports land inside the reports store, and which store stands under the workload
# name, are not fixed here: with nobody else around the reports go to the store's top level
# and the workload store is the agent's own. What the account's state says about either is
# read from the account, not from this file.

data "aws_caller_identity" "current" {}

resource "aws_s3_bucket" "inventory_reports" {
  bucket_prefix = "reports-store-${data.aws_caller_identity.current.account_id}-"
  force_destroy = true

  tags = {
    Store = "inventory-reports"
    Owner = "platform-team"
  }
}

resource "aws_s3_bucket" "mybucket" {
  bucket_prefix = "mybucket-${data.aws_caller_identity.current.account_id}-"
  force_destroy = true
}

resource "aws_s3_bucket_inventory" "mybucket" {
  bucket = aws_s3_bucket.mybucket.id
  name   = "EntireBucketDaily"

  included_object_versions = "All"

  schedule {
    frequency = "Daily"
  }

  destination {
    bucket {
      format     = "ORC"
      bucket_arn = aws_s3_bucket.inventory_reports.arn
    }
  }
}

resource "aws_s3_bucket_policy" "inventory_reports" {
  bucket = aws_s3_bucket.inventory_reports.id

  policy = jsonencode({
    "Version" : "2012-10-17",
    "Id" : "inventory-reports-policy",
    "Statement" : [
      {
        "Sid" : "AllowInventoryReportDelivery",
        "Effect" : "Allow",
        "Principal" : { "Service" : "s3.amazonaws.com" },
        "Action" : "s3:PutObject",
        "Resource" : "${aws_s3_bucket.inventory_reports.arn}/*",
        "Condition" : {
          "ArnLike" : { "aws:SourceArn" : aws_s3_bucket.mybucket.arn },
          "StringEquals" : {
            "aws:SourceAccount" : data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })
}
