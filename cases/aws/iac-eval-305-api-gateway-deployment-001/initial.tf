# Pre-existing: the cat-as-a-service backend as it stands before anyone asks for an HTTP front
# door. The pictures already live in this account's `cat-image…` bucket, the cat names in the
# `cat_names` table, and the function that serves both — `caas_cat` — is deployed and Active.
#
# It is not, however, wired to any of it. The function still runs as `caas_cat_legacy_role`, the
# identity it was first deployed under, which grants it nothing at all; the identity meant for
# it, `lambda_api_gateway_role`, stands empty beside it with no policy on it. And the account
# holds no REST API at all, so there is no `cat` resource, no GET or PUT method, no integration,
# no deployment and no `dev` stage, and the function's resource policy lets nothing invoke it.
#
# The function is deployed as Lambda deploys one: no layers on it, its logs going to its own
# default log group in the default text format, and the default 128 MB / 3 s it was created
# with.

resource "aws_dynamodb_table" "caas" {
  name         = "cat_names"
  hash_key     = "name"
  billing_mode = "PAY_PER_REQUEST"

  attribute {
    name = "name"
    type = "S"
  }
}

resource "aws_s3_bucket" "caas" {
  bucket_prefix = "cat-image"
}

resource "aws_iam_role" "lambda_role" {
  name = "lambda_api_gateway_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role" "caas_cat_legacy" {
  name = "caas_cat_legacy_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

data "archive_file" "caas_cat" {
  type        = "zip"
  output_path = "${path.module}/caas_cat.zip"
  source {
    filename = "caas_cat.py"
    content  = "import os\n\n\ndef handler(event, context):\n    return {\"statusCode\": 200, \"body\": \"meow\"}\n"
  }
}

resource "aws_lambda_function" "caas_cat" {
  function_name    = "caas_cat"
  role             = aws_iam_role.caas_cat_legacy.arn
  filename         = data.archive_file.caas_cat.output_path
  source_code_hash = data.archive_file.caas_cat.output_base64sha256
  handler          = "caas_cat.handler"
  runtime          = "python3.12"
}
