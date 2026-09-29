# Pre-existing: the code that must run when an EC2 image is created — the Lambda
# function `test_lambda` and the execution identity it runs as. Nothing delivers
# events to it yet: at S0 the account holds no EventBridge rule at all, no target
# and no statement in the function's resource policy, and the role carries no
# managed policy (the reference's AWSLambdaBasicExecutionRole attachment is part
# of the task's plumbing). There is no delivery path from any event source to the
# function at S0.

data "aws_iam_policy_document" "scan_assume_role" {
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

resource "aws_iam_role" "scan" {
  name               = "image_scan_role"
  assume_role_policy = data.aws_iam_policy_document.scan_assume_role.json
}

data "archive_file" "lambda-func" {
  type        = "zip"
  output_path = "${path.module}/lambda_func.zip"
  source {
    filename = "lambda_func.py"
    content  = "def handler(event, context):\n    return {\"ok\": True}\n"
  }
}

resource "aws_lambda_function" "scan" {
  function_name    = "test_lambda"
  role             = aws_iam_role.scan.arn
  filename         = data.archive_file.lambda-func.output_path
  source_code_hash = data.archive_file.lambda-func.output_base64sha256
  handler          = "lambda_func.handler"
  runtime          = "python3.12"
}
