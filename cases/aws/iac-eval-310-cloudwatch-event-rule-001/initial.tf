# Pre-existing: the code that must run daily — the Lambda function `cron-lambda-function`
# and the execution role it runs as. Nothing schedules it yet: there is no EventBridge rule,
# no target and no invoke permission at S0, and the role carries no managed policy (the
# reference's AWSLambdaBasicExecutionRole attachment is part of the task's plumbing).
#
# The function is on `python3.13` here, one runtime off the one the account standardises its
# Python workloads on; moving it is part of the task. Everything else about it stands on the
# provider's defaults — no description, no environment, timeout 3 s, memory 128 MB — so nothing
# another principal will put on it is present before anyone acts.

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
  runtime          = "python3.13"
}
