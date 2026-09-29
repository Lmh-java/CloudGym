resource "aws_iam_role" "dependency" {
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

data "archive_file" "dependency" {
  type        = "zip"
  output_path = "${path.module}/capability.zip"
  source {
    filename = "handler.py"
    content  = "def handler(event, context):\n    return {\"ok\": True}\n"
  }
}

resource "aws_lambda_function" "dependency" {
  function_name    = "cloudgym-capability-alias-fn"
  role             = aws_iam_role.dependency.arn
  filename         = data.archive_file.dependency.output_path
  source_code_hash = data.archive_file.dependency.output_base64sha256
  handler          = "handler.handler"
  runtime          = "python3.12"
}

resource "aws_lambda_alias" "capability" {
  name             = "live"
  function_name    = aws_lambda_function.dependency.function_name
  function_version = "$LATEST"
  description      = "cloudgym capability alias"
}
