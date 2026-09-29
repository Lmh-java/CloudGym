# IaC-Eval reference output for row 302 (provider/terraform blocks and the output dropped;
# the archive source inlined so the case is self-contained). The clean witness of the task
# alone: the pre-existing back of the service — the table, the bucket, the execution role and
# the deployed `caas_cat` — plus everything the task puts in front of it and the wiring that
# lets the function reach its two stores.
#
# The reference's `environment` block is dropped and the handler reads its bucket and table
# without one: the sandbox's SCP denies kms:Encrypt on the AWS-managed Lambda key, so
# UpdateFunctionConfiguration with an Environment is refused with AccessDeniedException for
# every principal in the account (certification round 1, 2026-09-23) and no final state can
# carry it. The handler the reference declares, caas_cat.handler, is part of the diff instead:
# at S0 the function still names the entry point of the package before this one.

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

  # Teardown hygiene, not part of the task: an agent that tries the API end to end
  # leaves a cat picture in the bucket, and destroy then fails with BucketNotEmpty
  # (certification round 2, 2026-09-23).
  force_destroy = true
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
          "s3:PutObject"
        ]
        Effect   = "Allow"
        Resource = "${aws_s3_bucket.caas.arn}/*"
      },
      {
        Action = [
          "dynamodb:PutItem"
        ]
        Effect   = "Allow"
        Resource = aws_dynamodb_table.caas.arn
      }
    ]
  })
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

data "archive_file" "caas_cat" {
  type        = "zip"
  output_path = "${path.module}/caas_cat.zip"

  source {
    filename = "caas_cat.py"
    content  = "import json\nimport random\nimport uuid\n\nimport boto3\n\ns3 = boto3.client(\"s3\")\nddb = boto3.client(\"dynamodb\")\nTABLE = \"cat_names\"\n\n\ndef _bucket():\n    for bucket in s3.list_buckets()[\"Buckets\"]:\n        if bucket[\"Name\"].startswith(\"cat-image\"):\n            return bucket[\"Name\"]\n    raise RuntimeError(\"no cat picture bucket in this account\")\n\n\ndef handler(event, context):\n    bucket = _bucket()\n    if event.get(\"httpMethod\") == \"PUT\":\n        name = str(uuid.uuid4())\n        s3.put_object(Bucket=bucket, Key=name, Body=b\"\")\n        ddb.put_item(TableName=TABLE, Item={\"name\": {\"S\": name}})\n        return {\"statusCode\": 201, \"body\": json.dumps({\"name\": name})}\n    keys = [o[\"Key\"] for o in s3.list_objects_v2(Bucket=bucket).get(\"Contents\", [])]\n    if not keys:\n        return {\"statusCode\": 404, \"body\": \"no cats yet\"}\n    return {\"statusCode\": 200, \"body\": json.dumps({\"name\": random.choice(keys)})}\n"
  }
}

resource "aws_lambda_function" "caas_cat" {
  function_name    = "caas_cat"
  role             = aws_iam_role.lambda_role.arn
  filename         = data.archive_file.caas_cat.output_path
  source_code_hash = data.archive_file.caas_cat.output_base64sha256
  handler          = "caas_cat.handler"
  runtime          = "python3.12"
}

resource "aws_api_gateway_integration" "caas_cat_get" {
  rest_api_id             = aws_api_gateway_rest_api.caas.id
  resource_id             = aws_api_gateway_resource.caas_cat.id
  http_method             = aws_api_gateway_method.caas_cat_get.http_method
  type                    = "AWS_PROXY"
  integration_http_method = "GET"
  uri                     = aws_lambda_function.caas_cat.invoke_arn
}

resource "aws_api_gateway_integration" "caas_cat_put" {
  rest_api_id             = aws_api_gateway_rest_api.caas.id
  resource_id             = aws_api_gateway_resource.caas_cat.id
  http_method             = aws_api_gateway_method.caas_cat_put.http_method
  type                    = "AWS_PROXY"
  integration_http_method = "PUT"
  uri                     = aws_lambda_function.caas_cat.invoke_arn
}

resource "aws_lambda_permission" "caas_cat" {
  action        = "lambda:InvokeFunction"
  principal     = "apigateway.amazonaws.com"
  function_name = aws_lambda_function.caas_cat.function_name

  source_arn = "${aws_api_gateway_rest_api.caas.execution_arn}/*/*"
}

resource "aws_api_gateway_deployment" "api_deployment" {
  rest_api_id = aws_api_gateway_rest_api.caas.id
  depends_on = [aws_api_gateway_integration.caas_cat_get,
  aws_api_gateway_integration.caas_cat_put]
}

resource "aws_api_gateway_stage" "api_stage" {
  deployment_id = aws_api_gateway_deployment.api_deployment.id
  rest_api_id   = aws_api_gateway_rest_api.caas.id
  stage_name    = "dev"
}
