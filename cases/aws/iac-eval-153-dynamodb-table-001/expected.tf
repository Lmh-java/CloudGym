# IaC-Eval reference output for row 153, as the clean witness of the task alone: the store whose
# change stream the app function is to process, the execution role that can read that stream, the
# grant that says so, the function running as that role, and the event source mapping that joins
# the two. Never applied.
#
# Deviations from the row's reference text, each of them the witness's or the case's choice
# rather than the task's:
#   * provider/terraform blocks dropped, the `archive_file` source inlined and the row's
#     `output` blocks dropped, so the case is self-contained;
#   * the runtime moved off the retired `nodejs18.x` onto `nodejs22.x`. AWS no longer accepts
#     `nodejs18.x` for a function, and the runtime is not part of the task: initial.tf stands the
#     function up on the same `nodejs22.x` this file carries;
#   * the row's inline `aws_iam_role_policy` written as a customer managed policy of the same
#     name with an attachment, so the grant is a resource of its own that can be seen on the
#     account rather than a property of the role;
#   * the bootstrap identity `lambda_app_bootstrap` carried over verbatim from initial.tf. The
#     row builds the function from scratch and mints `iam_for_lambda` for it; here the function
#     is already deployed on the bootstrap identity, so the task's work on the role is to create
#     `iam_for_lambda`, grant it the store's stream, and move the function onto it. The bootstrap
#     identity is left standing — the task never asks for it to be removed.

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

resource "aws_iam_policy" "dynamodb_lambda_policy" {
  name = "lambda-dynamodb-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AllowLambdaFunctionToCreateLogs"
        Effect   = "Allow"
        Action   = ["logs:*"]
        Resource = ["arn:aws:logs:*:*:*"]
      },
      {
        Sid    = "APIAccessForDynamoDBStreams"
        Effect = "Allow"
        Action = [
          "dynamodb:GetRecords",
          "dynamodb:GetShardIterator",
          "dynamodb:DescribeStream",
          "dynamodb:ListStreams"
        ]
        Resource = "${aws_dynamodb_table.example_table.arn}/stream/*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "dynamodb_lambda_policy" {
  role       = aws_iam_role.iam_for_lambda.name
  policy_arn = aws_iam_policy.dynamodb_lambda_policy.arn
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

resource "aws_lambda_event_source_mapping" "dynamodb_lambda_mapping" {
  event_source_arn  = aws_dynamodb_table.example_table.stream_arn
  function_name     = aws_lambda_function.example_lambda.arn
  starting_position = "LATEST"
}
