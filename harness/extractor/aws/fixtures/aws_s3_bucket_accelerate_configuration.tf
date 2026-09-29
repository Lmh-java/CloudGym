resource "aws_s3_bucket" "capability" {
  bucket_prefix = "cloudgym-capability-"
}

resource "aws_s3_bucket_accelerate_configuration" "capability" {
  bucket = aws_s3_bucket.capability.id
  status = "Enabled"
}
