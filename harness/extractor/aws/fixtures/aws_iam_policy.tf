resource "aws_iam_policy" "capability" {
  name_prefix = "cloudgym-capability-"
  description = "CloudGym extractor capability check"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "CloudGymSmokeRead"
      Effect   = "Allow"
      Action   = "s3:ListAllMyBuckets"
      Resource = "*"
    }]
  })
}
