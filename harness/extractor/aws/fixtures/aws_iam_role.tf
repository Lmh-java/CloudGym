resource "aws_iam_role" "capability" {
  name_prefix = "cloudgym-capability-"
  description = "CloudGym extractor capability check"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })
}
