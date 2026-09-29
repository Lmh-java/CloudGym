resource "aws_s3_bucket" "dependency" {
  bucket_prefix = "cloudgym-capability-"
  force_destroy = true
}

resource "aws_iam_role" "dependency" {
  name_prefix = "cloudgym-capability-"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "firehose.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "dependency" {
  name_prefix = "cloudgym-capability-"
  role        = aws_iam_role.dependency.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = ["s3:AbortMultipartUpload", "s3:GetBucketLocation", "s3:GetObject", "s3:ListBucket",
      "s3:ListBucketMultipartUploads", "s3:PutObject"]
      Resource = [aws_s3_bucket.dependency.arn, "${aws_s3_bucket.dependency.arn}/*"]
    }]
  })
}

# Direct PUT into S3: no source stream, no traffic, no cost while idle. Creation takes
# one to two minutes.
resource "aws_kinesis_firehose_delivery_stream" "capability" {
  name        = "cwcap-${aws_s3_bucket.dependency.id}" # Firehose caps names at 64 chars
  destination = "extended_s3"

  extended_s3_configuration {
    role_arn   = aws_iam_role.dependency.arn
    bucket_arn = aws_s3_bucket.dependency.arn
  }

  depends_on = [aws_iam_role_policy.dependency]
}
