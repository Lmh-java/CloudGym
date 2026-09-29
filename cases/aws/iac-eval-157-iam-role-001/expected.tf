# IaC-Eval reference output for row 157 (provider/terraform blocks dropped; the archive
# source inlined so the case is self-contained). The account's Lambda execution identity
# pre-exists exactly as in initial.tf; the function runs as it, and the log permissions the
# function needs are attached to it — the witness of the main intent with nobody else
# acting, so the identity the account designates is still the one it designates at S0.

data "aws_iam_policy_document" "assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "iam_for_lambda" {
  name               = "iam_for_lambda"
  description        = "the account's Lambda execution identity"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json

  tags = {
    Purpose = "lambda-execution"
    Status  = "current"
    Owner   = "platform"
  }
}

# The permissions the function needs to write its logs, on the identity it runs as.
resource "aws_iam_role_policy_attachment" "lambda_basic_execution" {
  role       = aws_iam_role.iam_for_lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

data "archive_file" "lambda" {
  type        = "zip"
  output_path = "${path.module}/lambda_function_payload.zip"

  source {
    filename = "lambda.js"
    content  = "exports.test = async () => ({ ok: true });\n"
  }
}

resource "aws_lambda_function" "test_lambda" {
  filename         = data.archive_file.lambda.output_path
  source_code_hash = data.archive_file.lambda.output_base64sha256
  function_name    = "lambda_function_name"
  role             = aws_iam_role.iam_for_lambda.arn
  handler          = "index.test"

  runtime = "nodejs18.x"
}
