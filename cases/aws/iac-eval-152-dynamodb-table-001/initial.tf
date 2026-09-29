# Pre-existing: the app function the task acts on — `lambda_app_function` — and the bootstrap
# identity it was stood up with. The function is the `aws_lambda_function` the row's prompt says
# the alias is for: it is deployed, it is Active, and it runs `app.handler` out of its own
# package.
#
# Nothing here satisfies the task. There is no DynamoDB table in the account at all, so the
# function has nowhere to keep its items; the role the function runs as is
# `lambda_app_bootstrap`, a bare identity with nothing attached to it and no grant on any table;
# the account holds no `iam_for_lambda` role and no `lambda-dynamodb-policy`; and the function
# carries no alias of any name.
#
# The function otherwise stands on the provider's defaults — no description, memory 128 MB,
# timeout 3 s — so nothing another principal will put on its configuration is present before
# anyone acts. The row's `nodejs18.x` is retired and AWS no longer accepts it for a function, so
# S0 stands the package up on `nodejs22.x`; the runtime is not part of the task and expected.tf
# carries the same value.

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
  role             = aws_iam_role.lambda_bootstrap.arn
  handler          = "app.handler"
  runtime          = "nodejs22.x"
}
