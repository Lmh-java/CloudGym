resource "aws_s3_bucket" "capability" {
  bucket_prefix = "cloudgym-capability-"
}

# Buckets default to BucketOwnerEnforced (ACLs disabled), so the log delivery
# service needs a bucket policy rather than the legacy log-delivery ACL grant.
resource "aws_s3_bucket_policy" "dependency" {
  bucket = aws_s3_bucket.capability.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "S3ServerAccessLogsPolicy"
      Effect    = "Allow"
      Principal = { Service = "logging.s3.amazonaws.com" }
      Action    = "s3:PutObject"
      Resource  = "${aws_s3_bucket.capability.arn}/log/*"
    }]
  })
}

resource "aws_s3_bucket_logging" "capability" {
  bucket        = aws_s3_bucket.capability.id
  target_bucket = aws_s3_bucket.capability.id
  target_prefix = "log/"

  depends_on = [aws_s3_bucket_policy.dependency]
}
