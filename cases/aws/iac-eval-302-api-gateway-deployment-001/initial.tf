# Pre-existing: the back of the cat-picture service. The handler `caas_cat` is
# deployed and its execution role `lambda_api_gateway_role` exists; the pictures
# already have a bucket (`cat-image…`) and the names a table (`cat_names`).
#
# Nothing stands in front of the function at S0: there is no REST API, no
# resource, no method, no integration, no deployment, no stage and no resource
# policy letting API Gateway invoke it. The function's handler still names the
# entry point of the package before this one, and its role carries no inline
# policy, so it could not read or write either store.
#
# The handler takes no environment: the sandbox's SCP denies kms:Encrypt on the
# AWS-managed Lambda key, so no function in this account can carry environment
# variables at all. It finds its bucket by prefix and names its table directly.

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
  handler          = "caas_cat.main"
  runtime          = "python3.12"
}
