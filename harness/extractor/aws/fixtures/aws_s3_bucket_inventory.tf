resource "aws_s3_bucket" "capability" {
  bucket_prefix = "cloudgym-capability-"
}

resource "aws_s3_bucket_inventory" "capability" {
  bucket                   = aws_s3_bucket.capability.id
  name                     = "cloudgym-capability"
  included_object_versions = "All"
  schedule {
    frequency = "Daily"
  }
  destination {
    bucket {
      format     = "CSV"
      bucket_arn = aws_s3_bucket.capability.arn
      prefix     = "inventory"
    }
  }
}
