resource "aws_s3_bucket" "capability" {
  bucket_prefix = "cloudgym-capability-"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "capability" {
  bucket = aws_s3_bucket.capability.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}
