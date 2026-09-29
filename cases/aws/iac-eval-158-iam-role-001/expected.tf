# IaC-Eval reference output for row 158 (provider/terraform blocks dropped; the archive_file
# source inlined so the case is self-contained). The execution role and its assume-role policy
# document pre-exist exactly as in initial.tf; the function, the log-writing grant the identity
# it runs as needs, and that grant's attachment are the task.
#
# Two literals of the row are adjusted so the witness is a state this account can actually
# hold: nodejs18.x is no longer accepted for a new function, so the witness carries the current
# Node.js the account takes; and the row's `index.test` entry point names a file the row's own
# archive (`lambda.js`) does not contain, so the witness keeps the row's exported entry `test`
# on the file the row packages. Everything else — the function name, the zip package, the role
# it runs as — is the row's.
#
# This is the clean witness of the task with nobody else acting: the function runs as
# `iam_for_lambda` and that identity carries a log-writing grant written for the workload. It
# is never applied; what the account currently keeps its workloads on, which identity it keeps
# in service and which grant it provides are read from the account, and the resolution policy
# says which of the two stands.

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

resource "aws_iam_policy" "lambda_logging" {
  name        = "lambda_function_name-logging"
  description = "log writing for lambda_function_name"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
      ]
      Resource = "*"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_logging" {
  role       = aws_iam_role.iam_for_lambda.name
  policy_arn = aws_iam_policy.lambda_logging.arn
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
  handler          = "lambda.test"

  runtime = "nodejs22.x"
}
