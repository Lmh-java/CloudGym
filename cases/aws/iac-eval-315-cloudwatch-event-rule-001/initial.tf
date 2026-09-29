# Pre-existing: the code that has to run every morning — the Lambda function
# `cron-lambda-function` and the execution role it runs as. Nothing schedules it yet.
#
# At S0 the account holds no EventBridge rule at all: no schedule for the daily 07:00 UTC
# slot, no rule under the name a cron job lands on, nothing staged for a move, no target on
# the function and no resource policy letting anything invoke it. Every description the task
# uses therefore picks out at most one thing at S0, and nothing here satisfies the task.
#
# The role carries no managed policy either: the reference's AWSLambdaBasicExecutionRole
# attachment is part of the task's plumbing.

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
    content  = "def lambda_handler(event, context):\n    return {\"ok\": True}\n"
  }
}

resource "aws_lambda_function" "cron" {
  function_name    = "cron-lambda-function"
  role             = aws_iam_role.cron.arn
  filename         = data.archive_file.lambda-func.output_path
  source_code_hash = data.archive_file.lambda-func.output_base64sha256
  handler          = "lambda_func.lambda_handler"
  runtime          = "python3.12"
}
