# IaC-Eval reference output for row 312 (provider/terraform blocks dropped; the archive
# source inlined so the case is self-contained). Never applied: this is the clean witness
# of the task carried out with nobody else acting on the account — a schedule rule of the
# workload's own, running as the workload's execution identity, with a grant pinned to it.

resource "aws_cloudwatch_event_rule" "cron" {
  schedule_expression = "cron(0 7 * * ? *)"

  role_arn = aws_iam_role.cron.arn
}

resource "aws_cloudwatch_event_target" "cron" {
  rule = aws_cloudwatch_event_rule.cron.name
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
  source_arn    = aws_cloudwatch_event_rule.cron.arn
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
