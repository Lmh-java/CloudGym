# IaC-Eval reference output for row 315 (provider/terraform blocks dropped, the archive
# source inlined so the case is self-contained). The function and the role it runs as
# pre-exist exactly as in initial.tf; the task is the schedule around them.
#
# This is the witness of the main intent with nobody else acting: the account runs no other
# schedule for the daily 07:00 UTC slot, nothing else answers to the name a cron job lands
# on, and nothing is staged for a move — so the workload's schedule is a rule of its own,
# created here, and the function's resource policy admits it. Never applied.

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

# --- the task: the daily schedule, the function on it, and the grant that lets it fire ----

resource "aws_cloudwatch_event_rule" "cron" {
  name                = "cron"
  description         = "Runs cron-lambda-function every day at 07:00 UTC"
  schedule_expression = "cron(0 7 * * ? *)"
  state               = "ENABLED"
}

resource "aws_cloudwatch_event_target" "cron" {
  rule = aws_cloudwatch_event_rule.cron.name
  arn  = aws_lambda_function.cron.arn
}

resource "aws_lambda_permission" "cron" {
  statement_id  = "AllowExecutionFromEventBridge"
  function_name = aws_lambda_function.cron.function_name
  action        = "lambda:InvokeFunction"
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.cron.arn
}

resource "aws_iam_role_policy_attachment" "cron" {
  role       = aws_iam_role.cron.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}
