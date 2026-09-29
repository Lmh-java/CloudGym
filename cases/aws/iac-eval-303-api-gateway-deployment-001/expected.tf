# IaC-Eval reference output for row 303 (provider/terraform blocks dropped, the archive source
# inlined and the bucket prefix qualified by the account id so the case is self-contained),
# written against the storage and handler that pre-exist in `initial.tf`.
#
# The split: the picture store, the name store, the handler's identity and the handler `caas_cat`
# itself are already standing and are copied verbatim from `initial.tf`; the row's own resources —
# the REST API `caas`, its `cat` resource, the `GET` and `PUT` methods on it, the two AWS_PROXY
# integrations onto the handler, the invoke permission, the deployment and the `dev` stage — are
# the task, together with the inline grant the handler's identity needs to use the two stores and
# the invocation limit the image path needs.
#
# Three deviations from the reference, recorded here:
#
#   * the handler carries no `environment` block, and the row's two variables live in its package
#     instead. Lambda encrypts a function's environment with the account's `aws/lambda` key under
#     the caller's identity, and the sandbox SCP denies `kms:Encrypt` outright (certification
#     round 1, 2026-09-23), so no function in this account can carry environment variables. The
#     one function-configuration change the request makes is `timeout` instead: the reference's
#     handler fetches an object from S3 and returns it, which does not fit the three seconds
#     Lambda allows by default.
#   * the integrations carry `integration_http_method = "POST"` rather than the reference's `GET`
#     and `PUT`. API Gateway invokes a Lambda proxy integration over POST whatever the method the
#     client called; the reference's values leave the endpoints unusable. The row's intent — an
#     AWS_PROXY integration behind each of the two methods — is unchanged, and the oracle does not
#     pin this attribute either way.
#   * the reference's `output "api_id"` is dropped: outputs are not cloud state and the case is
#     scored on what the account holds.
#
# This file is the witness of the task alone and is never applied.

data "aws_caller_identity" "current" {}

resource "aws_s3_bucket" "caas" {
  bucket_prefix = "cat-image-${data.aws_caller_identity.current.account_id}"
}

resource "aws_dynamodb_table" "caas" {
  name         = "cat_names"
  hash_key     = "name"
  billing_mode = "PAY_PER_REQUEST"

  attribute {
    name = "name"
    type = "S"
  }
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

resource "aws_iam_role_policy" "lambda_policy" {
  name = "lambda_policy"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket",
        ]
        Effect = "Allow"
        Resource = [
          aws_s3_bucket.caas.arn,
          "${aws_s3_bucket.caas.arn}/*",
        ]
      },
      {
        Action = [
          "dynamodb:PutItem",
        ]
        Effect   = "Allow"
        Resource = aws_dynamodb_table.caas.arn
      },
    ]
  })
}

data "archive_file" "caas_cat" {
  type        = "zip"
  output_path = "${path.module}/caas_cat.zip"

  source {
    filename = "caas_cat.py"
    content  = <<-PY
      import base64
      import random
      import uuid

      import boto3

      BUCKET = "${aws_s3_bucket.caas.id}"
      TABLE = "${aws_dynamodb_table.caas.id}"

      s3 = boto3.client("s3")
      ddb = boto3.client("dynamodb")


      def handler(event, context):
          if event.get("httpMethod") == "PUT":
              name = str(uuid.uuid4())
              s3.put_object(Bucket=BUCKET, Key=name,
                            Body=base64.b64decode(event.get("body") or ""))
              ddb.put_item(TableName=TABLE, Item={"name": {"S": name}})
              return {"statusCode": 201, "body": name}
          keys = [o["Key"] for o in s3.list_objects_v2(Bucket=BUCKET).get("Contents", [])]
          if not keys:
              return {"statusCode": 404, "body": "no cats yet"}
          picture = s3.get_object(Bucket=BUCKET, Key=random.choice(keys))["Body"].read()
          return {"statusCode": 200, "isBase64Encoded": True,
                  "headers": {"Content-Type": "image/jpeg"},
                  "body": base64.b64encode(picture).decode()}
    PY
  }
}

resource "aws_lambda_function" "caas_cat" {
  function_name    = "caas_cat"
  role             = aws_iam_role.lambda_role.arn
  filename         = data.archive_file.caas_cat.output_path
  source_code_hash = data.archive_file.caas_cat.output_base64sha256
  handler          = "caas_cat.handler"
  runtime          = "python3.12"
  timeout          = 30
}

resource "aws_api_gateway_rest_api" "caas" {
  name = "caas"
}

resource "aws_api_gateway_resource" "caas_cat" {
  rest_api_id = aws_api_gateway_rest_api.caas.id
  parent_id   = aws_api_gateway_rest_api.caas.root_resource_id
  path_part   = "cat"
}

resource "aws_api_gateway_method" "caas_cat_get" {
  rest_api_id   = aws_api_gateway_rest_api.caas.id
  resource_id   = aws_api_gateway_resource.caas_cat.id
  http_method   = "GET"
  authorization = "NONE"
}

resource "aws_api_gateway_method" "caas_cat_put" {
  rest_api_id   = aws_api_gateway_rest_api.caas.id
  resource_id   = aws_api_gateway_resource.caas_cat.id
  http_method   = "PUT"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "caas_cat_get" {
  rest_api_id             = aws_api_gateway_rest_api.caas.id
  resource_id             = aws_api_gateway_resource.caas_cat.id
  http_method             = aws_api_gateway_method.caas_cat_get.http_method
  type                    = "AWS_PROXY"
  integration_http_method = "POST"
  uri                     = aws_lambda_function.caas_cat.invoke_arn
}

resource "aws_api_gateway_integration" "caas_cat_put" {
  rest_api_id             = aws_api_gateway_rest_api.caas.id
  resource_id             = aws_api_gateway_resource.caas_cat.id
  http_method             = aws_api_gateway_method.caas_cat_put.http_method
  type                    = "AWS_PROXY"
  integration_http_method = "POST"
  uri                     = aws_lambda_function.caas_cat.invoke_arn
}

resource "aws_lambda_permission" "caas_cat" {
  statement_id  = "AllowExecutionFromAPIGateway"
  action        = "lambda:InvokeFunction"
  principal     = "apigateway.amazonaws.com"
  function_name = aws_lambda_function.caas_cat.function_name
  source_arn    = "${aws_api_gateway_rest_api.caas.execution_arn}/*/*"
}

resource "aws_api_gateway_deployment" "api_deployment" {
  rest_api_id = aws_api_gateway_rest_api.caas.id

  depends_on = [
    aws_api_gateway_integration.caas_cat_get,
    aws_api_gateway_integration.caas_cat_put,
  ]
}

resource "aws_api_gateway_stage" "api_stage" {
  deployment_id = aws_api_gateway_deployment.api_deployment.id
  rest_api_id   = aws_api_gateway_rest_api.caas.id
  stage_name    = "dev"
}
