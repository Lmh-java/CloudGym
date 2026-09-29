# Pre-existing: the code that has to run every day — the Lambda function
# `cron-lambda-function` and the execution identity it runs as. Nothing drives it
# yet: at S0 the account holds no EventBridge rule at all, so there is no schedule,
# no target and no statement in the function's resource policy, and the role carries
# no managed policy (the reference's AWSLambdaBasicExecutionRole attachment is part
# of the task's plumbing). The execution identity is assumable by the function
# service and, as the account stands, by the event service too — nothing has taken
# the two apart yet.

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
