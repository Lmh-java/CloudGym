# Pre-existing: the cat-picture service's storage and its handler, standing in the account
# before anyone asks for a way in from the internet. Four things are already here:
#
#   * the picture store, an S3 bucket named off the `cat-image` prefix;
#   * the name store, the DynamoDB table `cat_names`;
#   * `lambda_api_gateway_role`, the identity the handler runs as — assumable by the Lambda
#     service and holding nothing else: no grant on the bucket, none on the table;
#   * `caas_cat`, the handler itself: the code that stores an uploaded picture and hands a
#     random one back. Its package carries the two store names, so it needs nothing from its
#     environment; what it does not have is the permission to touch either store.
#
# Nothing of the task is here. The account holds no REST API, no resource, no method, no
# integration, no deployment and no stage; the function carries no resource policy, so nothing
# may invoke it; the role has no inline policy at all; and the function still stands on the
# Lambda default of three seconds for an invocation, which is not enough to fetch and return an
# image. Nothing here carries a norm either: the function says nothing about itself (no
# description) and stands on the default memory, so a baseline or a marking observed later was
# written after S0.
#
# Two things differ from the reference, both forced by the account:
#
#   * `bucket_prefix` replaces the reference's fixed prefix so the name carries the account id:
#     S3 bucket names are global, and the arms of a run must not contend for one. 10 + 12 is
#     inside the 37-character prefix limit.
#   * the handler takes its two store names from its package rather than from environment
#     variables. Lambda encrypts a function's environment with the account's `aws/lambda` key
#     under the caller's identity, and the sandbox SCP denies `kms:Encrypt` outright
#     (certification round 1, 2026-09-23: every `UpdateFunctionConfiguration` carrying an
#     environment block is refused with `AccessDeniedException`), so no function in this account
#     can carry environment variables at all.

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
}
