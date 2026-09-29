# IaC-Eval reference output for row 274 (provider/terraform blocks dropped; the pre-existing
# reports store copied verbatim from initial.tf). The clean witness of the task with nobody
# else around: the store the row asks to create for the application's export objects, its
# weekly CSV inventory of current object versions, and the delivery of that report into the
# store the account already keeps for inventory reports.
#
# Two deviations from the row's reference text, both forced by what S3 accepts:
#
#   * the row names its buckets `my-tf-test-bucket` / `my-tf-inventory-bucket`, placeholders in
#     a global namespace no account can actually take, so both stores are named as this account
#     names stores, and marked for what they keep — the reports store exactly as initial.tf
#     declares it;
#   * the row omits the destination bucket policy. S3 delivers an inventory report only to a
#     destination whose policy admits the service for it, so the reference's `bucket_arn`
#     destination is only a report in an account where that grant exists; it is part of the
#     task ("make sure that store accepts the delivery"), not an invention beside it.

data "aws_caller_identity" "current" {}

resource "aws_s3_bucket" "reports" {
  bucket_prefix = "store-${data.aws_caller_identity.current.account_id}-"
  force_destroy = true

  tags = {
    Store = "inventory-reports"
    Owner = "storage-platform"
  }
}

resource "aws_s3_bucket" "exports" {
  bucket_prefix = "store-${data.aws_caller_identity.current.account_id}-"
  force_destroy = true

  tags = {
    Store = "app-exports"
    Owner = "orders-team"
  }
}

resource "aws_s3_bucket_inventory" "exports_weekly" {
  bucket = aws_s3_bucket.exports.id
  name   = "EntireBucketWeekly"

  included_object_versions = "Current"

  schedule {
    frequency = "Weekly"
  }

  destination {
    bucket {
      format     = "CSV"
      bucket_arn = aws_s3_bucket.reports.arn
    }
  }
}

resource "aws_s3_bucket_policy" "reports" {
  bucket = aws_s3_bucket.reports.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "InventoryReportDelivery"
      Effect    = "Allow"
      Principal = { Service = "s3.amazonaws.com" }
      Action    = "s3:PutObject"
      Resource  = "${aws_s3_bucket.reports.arn}/*"
      Condition = {
        StringEquals = {
          "aws:SourceAccount" = data.aws_caller_identity.current.account_id
        }
        ArnLike = {
          "aws:SourceArn" = aws_s3_bucket.exports.arn
        }
      }
    }]
  })
}
