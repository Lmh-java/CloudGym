# Pre-existing: the two standing pieces of the clickstream ingestion workload — the identity
# the workload delivers as, and the code that reshapes a record on its way through.
#
# `clickstream-delivery-role` is the workload's one identity. It is trusted by both the
# delivery service and the function service because the same workload runs as it on both
# sides, which is how this account keeps a single identity per workload rather than one per
# service. It holds no grant at all: no inline policy, no managed policy attached, so nothing
# in the account may write anything anywhere on its behalf yet.
#
# `clickstream-record-transform` is the function that reshapes a record. It stands on the
# provider's defaults in every respect the task and the other owners of this account care
# about — timeout 3 s, memory 128 MB, no description — so nothing another principal will put
# on it is present before anyone acts.
#
# Nothing here satisfies the task: the account holds no S3 bucket for the archive, no delivery
# stream of any kind, the role carries no grant, and the function is nowhere near the
# 60-second timeout a transformation invocation needs.

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
}
