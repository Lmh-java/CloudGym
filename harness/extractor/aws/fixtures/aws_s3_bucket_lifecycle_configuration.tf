resource "aws_s3_bucket" "capability" {
  bucket_prefix = "cloudgym-capability-"
}

resource "aws_s3_bucket_lifecycle_configuration" "capability" {
  bucket = aws_s3_bucket.capability.id

  rule {
    id     = "capability-check"
    status = "Enabled"
    filter {}

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }
  }
}
