resource "aws_s3_bucket" "capability" {
  bucket_prefix = "cloudgym-capability-"
}

resource "aws_s3_bucket_intelligent_tiering_configuration" "capability" {
  bucket = aws_s3_bucket.capability.id
  name   = "cloudgym-capability"
  tiering {
    access_tier = "ARCHIVE_ACCESS"
    days        = 90
  }
}
