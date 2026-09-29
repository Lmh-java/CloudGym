resource "aws_s3_bucket" "capability" {
  bucket_prefix = "cloudgym-capability-"
}

resource "aws_s3_bucket_website_configuration" "capability" {
  bucket = aws_s3_bucket.capability.id
  index_document {
    suffix = "index.html"
  }
  error_document {
    key = "error.html"
  }
}
