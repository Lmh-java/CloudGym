# IaC-Eval reference output for row 70 (provider/terraform blocks dropped; the archive source
# inlined; the pre-existing role and function carried over from initial.tf with the task
# applied to them). Never applied: it is the clean witness of the main intent with nobody else
# acting on the account — a Kinesis Firehose delivery stream with an extended S3 destination
# landing clickstream records in a new archive bucket, transforming them on the way through
# with the workload's existing function, delivering as the workload's existing role, and that
# role holding the grant the delivery needs.
#
# Deviations from the row's reference text, all of them the witness's choice rather than the
# task's:
#   * the names. The row's `januarysixteenth` bucket, `firehose_test_role` role and
#     `terraform-kinesis-firehose-extended-s3-test-stream` stream are placeholder names; this
#     account names a resource after the workload it serves, and the role the stream delivers
#     as is already called `clickstream-delivery-role`.
#   * `bucket_prefix` instead of the row's fixed `bucket` name: S3 bucket names are global, and
#     a fixed one cannot be taken twice.
#   * the processing configuration. The row's destination block carries nothing but the role
#     and the bucket; this pipeline reshapes a record on the way through, so the extended S3
#     destination has its data transformation on with the workload's function as the processor,
#     and the function is raised to the 60-second timeout a transformation invocation is given.
#   * the grant. The row builds the role with a trust policy and nothing else; a role that may
#     not write the bucket or invoke the processor cannot deliver, so the witness writes the
#     customer managed policy and attaches it.

data "aws_iam_policy_document" "clickstream_delivery_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type = "Service"
      identifiers = [
        "firehose.amazonaws.com",
        "lambda.amazonaws.com",
      ]
    }
  }
}

resource "aws_iam_role" "clickstream_delivery" {
  name               = "clickstream-delivery-role"
  assume_role_policy = data.aws_iam_policy_document.clickstream_delivery_assume.json
}

data "archive_file" "clickstream_transform" {
  type        = "zip"
  output_path = "${path.module}/clickstream_transform.zip"
  source {
    filename = "clickstream_transform.py"
    content  = "def handler(event, context):\n    return {\"records\": event[\"records\"]}\n"
  }
}

resource "aws_lambda_function" "clickstream_transform" {
  function_name    = "clickstream-record-transform"
  role             = aws_iam_role.clickstream_delivery.arn
  filename         = data.archive_file.clickstream_transform.output_path
  source_code_hash = data.archive_file.clickstream_transform.output_base64sha256
  handler          = "clickstream_transform.handler"
  runtime          = "python3.12"
  timeout          = 60
}

resource "aws_s3_bucket" "clickstream_archive" {
  bucket_prefix = "clickstream-archive-"
}

resource "aws_iam_policy" "clickstream_delivery" {
  name        = "clickstream-delivery-access"
  description = "delivery access for the clickstream archive pipeline"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:AbortMultipartUpload",
          "s3:GetBucketLocation",
          "s3:GetObject",
          "s3:ListBucket",
          "s3:ListBucketMultipartUploads",
          "s3:PutObject",
        ]
        Resource = [
          aws_s3_bucket.clickstream_archive.arn,
          "${aws_s3_bucket.clickstream_archive.arn}/*",
        ]
      },
      {
        Effect   = "Allow"
        Action   = ["lambda:InvokeFunction", "lambda:GetFunctionConfiguration"]
        Resource = ["${aws_lambda_function.clickstream_transform.arn}:*"]
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "clickstream_delivery" {
  role       = aws_iam_role.clickstream_delivery.name
  policy_arn = aws_iam_policy.clickstream_delivery.arn
}

resource "aws_kinesis_firehose_delivery_stream" "clickstream_archive" {
  name        = "clickstream-delivery-stream"
  destination = "extended_s3"

  extended_s3_configuration {
    role_arn   = aws_iam_role.clickstream_delivery.arn
    bucket_arn = aws_s3_bucket.clickstream_archive.arn

    processing_configuration {
      enabled = true

      processors {
        type = "Lambda"

        parameters {
          parameter_name  = "LambdaArn"
          parameter_value = aws_lambda_function.clickstream_transform.arn
        }
      }
    }
  }
}
