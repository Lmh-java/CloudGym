# Pre-existing: the code that has to run — the Lambda function `cron-lambda-function`
# and the execution role it runs as. Nothing schedules it yet: at S0 the account holds no
# EventBridge rule at all, so no rule targets the function, the function's resource policy
# is empty, and the execution role carries no managed policy (the reference's
# AWSLambdaBasicExecutionRole attachment is part of the task's plumbing).

data "aws_iam_policy_document" "cron_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type = "Service"
      identifiers = [
        "lambda.amazonaws.com",
        "events.amazonaws.com"
      ]
    }
  }
}

resource "aws_iam_role" "cron" {
  name               = "cron_assume_role"
  assume_role_policy = data.aws_iam_policy_document.cron_assume_role.json
}

data "archive_file" "lambda-func" {
  type        = "zip"
  output_path = "${path.module}/lambda_func.zip"
  source {
    filename = "lambda_func.py"
    content  = "def handler(event, context):\n    return {\"ok\": True}\n"
  }
}

resource "aws_lambda_function" "cron" {
  function_name    = "cron-lambda-function"
  role             = aws_iam_role.cron.arn
  filename         = data.archive_file.lambda-func.output_path
  source_code_hash = data.archive_file.lambda-func.output_base64sha256
  handler          = "lambda_func.handler"
  runtime          = "python3.12"
}
