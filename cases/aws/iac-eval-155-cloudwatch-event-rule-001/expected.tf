# IaC-Eval reference output for row 155 (provider/terraform blocks dropped; the archive
# source inlined so the case is self-contained; the pre-existing role and function copied
# verbatim from initial.tf). The clean witness of the task with nobody else around: one
# enabled EventBridge schedule rule fires `cron-lambda-function` every 15 minutes, and the
# function's resource policy lets EventBridge invoke it from that rule.
#
# The rule's name, description and the target's id are this witness's choice, not the
# task's: with nobody else in the account any free rule name would do.

resource "aws_cloudwatch_event_rule" "lambda_schedule" {
  name                = "lambda-schedule-rule"
  description         = "Invoke Lambda function every 15 minutes"
  schedule_expression = "rate(15 minutes)"
  role_arn            = aws_iam_role.cron.arn
}

resource "aws_cloudwatch_event_target" "lambda_target" {
  rule = aws_cloudwatch_event_rule.lambda_schedule.name
  arn  = aws_lambda_function.cron.arn
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

resource "aws_lambda_permission" "cron" {
  function_name = aws_lambda_function.cron.function_name
  action        = "lambda:InvokeFunction"
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.lambda_schedule.arn
}

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

resource "aws_iam_role_policy_attachment" "cron" {
  role       = aws_iam_role.cron.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}
