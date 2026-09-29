# Pre-existing: the clickstream analytics pipeline as this account holds it today — the Managed
# Service for Apache Flink application `clickstream-analytics`, and the shared bootstrap identity
# it was stood up on.
#
# `analytics-bootstrap-role` is the identity every analytics workload in this account is first
# stood up on: trusted by the analytics service, holding no grant at all — no inline policy, no
# managed policy attached — so nothing running as it may read or write anything anywhere yet. It
# is shared, which is why it is not any one application's own identity.
#
# `clickstream-analytics` is the application itself. It stands on the provider's defaults in
# every respect the task and the other owners of this account care about: no application
# configuration of any kind — no monitoring settings, no checkpointing settings, no environment
# properties — and no description, so nothing another principal will put on it is present before
# anyone acts.
#
# Nothing here satisfies the task: the account holds no log group for the application, no
# artifacts bucket, no identity of the application's own and no grant anywhere, and the
# application still runs as the shared bootstrap role.

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

resource "aws_kinesisanalyticsv2_application" "clickstream" {
  name                   = "clickstream-analytics"
  runtime_environment    = "FLINK-1_20"
  service_execution_role = aws_iam_role.analytics_bootstrap.arn
}
