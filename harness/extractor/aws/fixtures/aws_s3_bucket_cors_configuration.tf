resource "aws_s3_bucket" "capability" {
  bucket_prefix = "cloudgym-capability-"
}

resource "aws_s3_bucket_cors_configuration" "capability" {
  bucket = aws_s3_bucket.capability.id
  cors_rule {
    allowed_headers = ["*"]
    allowed_methods = ["GET"]
    allowed_origins = ["https://example.com"]
    max_age_seconds = 3000
  }
}
