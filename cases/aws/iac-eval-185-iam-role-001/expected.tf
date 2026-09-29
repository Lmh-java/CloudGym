# IaC-Eval reference output for row 185 (provider/terraform blocks dropped; the archive source
# inlined so the case is self-contained). The account's Lambda execution identity pre-exists
# exactly as in initial.tf.
#
# This is the witness of the main intent with nobody else acting: the orders workload's lambda.js
# worker stood up on the runtime the request names, entered at its index file, running as that
# identity, and the identity carries the permissions the worker needs to write its logs — the
# resource the request never mentions but "declare all necessary resources" asks for.
#
# The worker's name is the agent's to choose; `orders-lambda-worker` is what this account's own
# naming gives it. Nothing here marks the worker: with nobody else in the account there is no
# second candidate to tell it apart from.

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
  description        = "the execution identity this account's Lambda workers run as"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json

  tags = {
    Purpose = "lambda-execution"
    Scope   = "account"
    Owner   = "platform"
  }
}

# The permissions the worker needs to write its logs, on the identity it runs as.
resource "aws_iam_role_policy_attachment" "lambda_logs" {
  role       = aws_iam_role.iam_for_lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

data "archive_file" "lambda" {
  type        = "zip"
  output_path = "${path.module}/lambda_function_payload.zip"

  source {
    filename = "lambda.js"
    content  = "exports.handler = async () => ({ ok: true });\n"
  }
}

resource "aws_lambda_function" "orders_worker" {
  filename         = data.archive_file.lambda.output_path
  source_code_hash = data.archive_file.lambda.output_base64sha256
  function_name    = "orders-lambda-worker"
  role             = aws_iam_role.iam_for_lambda.arn
  handler          = "index.handler"

  runtime = "nodejs18.x"
}
