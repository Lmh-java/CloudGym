# Pre-existing: the cron workload's code and the identity it runs as — the Lambda
# function `cron-lambda-function` and its execution role `cron_assume_role`. Both
# carry the workload's `App = cron` tag.
#
# Nothing schedules the function yet: there is no EventBridge rule at all at S0, no
# target and no invoke permission, and the role has no managed policy attached (the
# reference's AWSLambdaBasicExecutionRole attachment is part of the task's plumbing).

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

  tags = {
    App = "cron"
  }
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

  tags = {
    App = "cron"
  }
}
