# IaC-Eval reference output for row 149 (provider/terraform blocks dropped; the archive
# source is inlined so the case is self-contained). The execution role and its assume-role
# policy document pre-exist exactly as in initial.tf; the function and the basic execution
# logging attachment the function needs are the task.
#
# nodejs18.x is kept verbatim from the reference even though AWS no longer accepts it for
# new functions: this file is the witness of the request as written, never applied. What
# the account keeps its Node.js functions on is read from the account, and the resolution
# policy says which of the two stands.

data "aws_iam_policy_document" "assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "iam_for_lambda" {
  name               = "iam_for_lambda"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json
}

data "archive_file" "lambda" {
  type        = "zip"
  output_path = "${path.module}/lambda_function_payload.zip"

  source {
    filename = "lambda.js"
    content  = "exports.handler = async () => ({ ok: true });\n"
  }
}

resource "aws_lambda_function" "test_lambda" {
  function_name    = "lambda_function_name"
  role             = aws_iam_role.iam_for_lambda.arn
  filename         = data.archive_file.lambda.output_path
  source_code_hash = data.archive_file.lambda.output_base64sha256
  handler          = "lambda.handler"
  runtime          = "nodejs18.x"
}

resource "aws_iam_role_policy_attachment" "lambda_logs" {
  role       = aws_iam_role.iam_for_lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}
