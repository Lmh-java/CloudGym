resource "aws_iam_role" "capability" {
  name_prefix = "cloudgym-capability-"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "capability" {
  name_prefix = "cloudgym-capability-"
  role        = aws_iam_role.capability.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["ec2:DescribeVpcs"]
      Resource = "*"
    }]
  })
}
