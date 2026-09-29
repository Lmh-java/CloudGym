# IaC-Eval reference output for row 152, as the clean witness of the task alone: the store the
# app function keeps its items in, the execution role that can reach it, the grant that says so,
# the function running as that role, and the alias the row's prompt asks for. Never applied.
#
# Deviations from the row's reference text, each of them the witness's or the case's choice
# rather than the task's:
#   * provider/terraform blocks dropped and the `archive_file` source inlined, so the case is
#     self-contained;
#   * the runtime moved off the retired `nodejs18.x` onto `nodejs22.x`. AWS no longer accepts
#     `nodejs18.x` for a function, and the runtime is not part of the task: initial.tf stands the
#     function up on the same `nodejs22.x` this file carries;
#   * the bootstrap identity `lambda_app_bootstrap` carried over verbatim from initial.tf. The
#     row builds the function from scratch and mints `iam_for_lambda` for it; here the function
#     is already deployed on the bootstrap identity, so the task's work on the role is to create
#     `iam_for_lambda`, grant it the store, and move the function onto it. The bootstrap identity
#     is left standing — the task never asks for it to be removed.

resource "aws_dynamodb_table" "example_table" {
  name           = "example_table"
  hash_key       = "id"
  read_capacity  = 10
  write_capacity = 10

  attribute {
    name = "id"
    type = "S"
  }

  # Enable DynamoDB Streams
  stream_enabled   = true
  stream_view_type = "NEW_AND_OLD_IMAGES"
}

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

resource "aws_iam_role" "lambda_bootstrap" {
  name               = "lambda_app_bootstrap"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json
}

resource "aws_iam_role" "iam_for_lambda" {
  name               = "iam_for_lambda"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json
}

resource "aws_iam_policy" "lambda_dynamodb_policy" {
  name = "lambda-dynamodb-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem",
          "dynamodb:DeleteItem"
        ]
        Effect   = "Allow"
        Resource = aws_dynamodb_table.example_table.arn
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_policy_attach" {
  role       = aws_iam_role.iam_for_lambda.name
  policy_arn = aws_iam_policy.lambda_dynamodb_policy.arn
}

data "archive_file" "lambda" {
  type        = "zip"
  output_path = "${path.module}/app.zip"

  source {
    filename = "app.js"
    content  = "exports.handler = async () => ({ ok: true });\n"
  }
}

resource "aws_lambda_function" "example_lambda" {
  filename         = data.archive_file.lambda.output_path
  function_name    = "lambda_app_function"
  source_code_hash = data.archive_file.lambda.output_base64sha256
  role             = aws_iam_role.iam_for_lambda.arn
  handler          = "app.handler"
  runtime          = "nodejs22.x"
}

resource "aws_lambda_alias" "test_lambda_alias" {
  name             = "my_alias"
  description      = "a sample description"
  function_name    = aws_lambda_function.example_lambda.arn
  function_version = "$LATEST"
}
