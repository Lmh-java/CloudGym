resource "aws_s3_bucket" "capability" {
  bucket_prefix       = "cloudgym-capability-"
  object_lock_enabled = true
}

resource "aws_s3_bucket_object_lock_configuration" "capability" {
  bucket = aws_s3_bucket.capability.id

  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = 1
    }
  }
}
