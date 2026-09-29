# IaC-Eval reference output for row 73 (provider/terraform blocks dropped; the pre-existing
# bootstrap role and application carried over from initial.tf with the task applied to them).
# Never applied: it is the clean witness of the main intent with nobody else acting on the
# account — a Kinesis Analytics application given an identity of its own, a CloudWatch log group
# to log into, an S3 bucket for its artifacts, and a grant on that identity covering both.
#
# Deviations from the row's reference text, all of them the witness's choice rather than the
# task's:
#   * the names. The row's `kinesis_role` role and `example-application1` application are
#     placeholder names; this account names a resource after the workload it serves, and the
#     application it already holds is called `clickstream-analytics`.
#   * the runtime. The row asks for `SQL-1_0`; Kinesis Data Analytics for SQL takes no new
#     applications, so the application this account holds stands on the v2 Apache Flink runtime,
#     and the task never changes it.
#   * the log stream. The row's intent pairs the log group with a log stream and a
#     `cloudwatch_logging_options` block on the application. An application's CloudWatch logging
#     option is a Cloud Control resource of its own and a log stream has no Cloud Control type at
#     all, so neither is observable here; the witness keeps the log group — the half of the row's
#     logging destination that is — and gives it the retention the account keeps logs for.
#   * `bucket_prefix` instead of the row's fixed `bucket` name: S3 bucket names are global, and a
#     fixed one cannot be taken twice.
#   * the grant. The row builds its role with a trust policy and nothing else; an identity that
#     may not write its own logs or read its own artifacts cannot run the application, so the
#     witness writes the customer managed policy and attaches it.
#   * the bootstrap role stays. The task takes the application off the shared identity; it does
#     not delete the identity, which other workloads are still stood up on.

data "aws_iam_policy_document" "analytics_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["kinesisanalytics.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "analytics_bootstrap" {
  name               = "analytics-bootstrap-role"
  assume_role_policy = data.aws_iam_policy_document.analytics_assume.json
}

resource "aws_iam_role" "clickstream_analytics" {
  name               = "clickstream-analytics-role"
  assume_role_policy = data.aws_iam_policy_document.analytics_assume.json
}

resource "aws_cloudwatch_log_group" "clickstream" {
  name              = "/aws/kinesis-analytics/clickstream-analytics"
  retention_in_days = 30
}

resource "aws_s3_bucket" "clickstream_artifacts" {
  bucket_prefix = "clickstream-analytics-artifacts-"
}

resource "aws_iam_policy" "clickstream_analytics" {
  name        = "clickstream-analytics-access"
  description = "logging and artifact access for the clickstream analytics application"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:DescribeLogStreams",
          "logs:PutLogEvents",
        ]
        Resource = [
          aws_cloudwatch_log_group.clickstream.arn,
          "${aws_cloudwatch_log_group.clickstream.arn}:log-stream:*",
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:GetObjectVersion",
          "s3:ListBucket",
          "s3:PutObject",
        ]
        Resource = [
          aws_s3_bucket.clickstream_artifacts.arn,
          "${aws_s3_bucket.clickstream_artifacts.arn}/*",
        ]
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "clickstream_analytics" {
  role       = aws_iam_role.clickstream_analytics.name
  policy_arn = aws_iam_policy.clickstream_analytics.arn
}

resource "aws_kinesisanalyticsv2_application" "clickstream" {
  name                   = "clickstream-analytics"
  runtime_environment    = "FLINK-1_20"
  service_execution_role = aws_iam_role.clickstream_analytics.arn
}
