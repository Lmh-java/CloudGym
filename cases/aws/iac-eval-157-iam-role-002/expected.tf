# IaC-Eval reference output for row 157, as the clean witness of the task alone:
# provider/terraform blocks dropped, the `archive_file` source inlined so the case is
# self-contained, the runtime moved off the retired `nodejs18.x`, and the basic-execution
# attachment that "define the IAM roles as needed" implies made explicit. The pooled
# execution identity from initial.tf is carried over verbatim; the reference does not use
# it — it mints `iam_for_lambda` of its own, which is exactly what the task looks like with
# nobody else around and no account conventions consulted.

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

resource "aws_iam_role" "pool_1" {
  name               = "lambda-exec-pool-1"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json
  description        = "Pooled Lambda execution identity"

  tags = {
    ManagedBy = "identity-platform"
    Workload  = "unassigned"
  }
}

resource "aws_iam_role" "iam_for_lambda" {
  name               = "iam_for_lambda"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json
}

resource "aws_iam_role_policy_attachment" "iam_for_lambda" {
  role       = aws_iam_role.iam_for_lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

data "archive_file" "lambda" {
  type        = "zip"
  output_path = "${path.module}/lambda_function_payload.zip"
  source {
    filename = "lambda.js"
    content  = "exports.test = async (event) => ({ statusCode: 200, body: \"ok\" });\n"
  }
}

resource "aws_lambda_function" "test_lambda" {
  function_name    = "lambda_function_name"
  role             = aws_iam_role.iam_for_lambda.arn
  filename         = data.archive_file.lambda.output_path
  source_code_hash = data.archive_file.lambda.output_base64sha256
  handler          = "index.test"
  runtime          = "nodejs22.x"
}
