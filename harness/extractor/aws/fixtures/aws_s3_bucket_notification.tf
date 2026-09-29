resource "aws_s3_bucket" "capability" {
  bucket_prefix = "cloudgym-capability-"
}

resource "aws_s3_bucket_notification" "capability" {
  bucket      = aws_s3_bucket.capability.id
  eventbridge = true
}
