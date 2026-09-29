resource "aws_s3_bucket" "capability" {
  bucket_prefix = "cloudgym-capability-"

  tags = {
    Purpose = "extractor-capability-check"
  }
}
