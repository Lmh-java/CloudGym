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

data "archive_file" "capability" {
  type        = "zip"
  output_path = "${path.module}/capability.zip"
  source {
    filename = "handler.py"
    content  = "def handler(event, context):\n    return {\"ok\": True}\n"
  }
}

resource "aws_lambda_function" "capability" {
  function_name    = "cloudgym-capability-perm"
  role             = aws_iam_role.capability.arn
  filename         = data.archive_file.capability.output_path
  source_code_hash = data.archive_file.capability.output_base64sha256
  handler          = "handler.handler"
  runtime          = "python3.12"
}

resource "aws_lambda_permission" "capability" {
  statement_id  = "cloudgym-capability-check"
  function_name = aws_lambda_function.capability.function_name
  action        = "lambda:InvokeFunction"
  principal     = "events.amazonaws.com"
}
