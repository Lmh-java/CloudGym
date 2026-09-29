resource "aws_s3_bucket" "capability" {
  bucket_prefix = "cloudgym-capability-"
}

resource "aws_s3_bucket_ownership_controls" "capability" {
  bucket = aws_s3_bucket.capability.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}
