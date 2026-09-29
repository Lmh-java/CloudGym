resource "aws_s3_bucket" "dependency" {
  bucket_prefix = "cloudgym-capability-"
}

resource "aws_s3_bucket_policy" "capability" {
  bucket = aws_s3_bucket.dependency.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [aws_s3_bucket.dependency.arn, "${aws_s3_bucket.dependency.arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}
