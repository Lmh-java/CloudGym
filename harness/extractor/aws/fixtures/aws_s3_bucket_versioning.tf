resource "aws_s3_bucket" "capability" {
  bucket_prefix = "cloudgym-capability-"
}

resource "aws_s3_bucket_versioning" "capability" {
  bucket = aws_s3_bucket.capability.id
  versioning_configuration {
    status = "Enabled"
  }
}
