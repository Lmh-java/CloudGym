# Pre-existing: the telemetry delivery path, as it stands before anyone asks for New Relic.
# `telemetry-events-stream` is the live Firehose stream the applications in this account write
# their telemetry into; it posts its records to the in-house collector over HTTP and sets aside
# the ones the collector refuses in the account's telemetry backup store, delivering as the
# `telemetry-firehose-delivery` identity.
#
# Why the stream already has an HTTP endpoint destination: a Firehose destination is updated in
# place by `firehose:UpdateDestination`, and that is the one call the task's work consists of. A
# stream that already posts over HTTP is therefore the initial state in which the row's task is a
# change to a live delivery path rather than a from-scratch build; what the task changes is
# *which* endpoint it posts to, how much it accumulates before it posts, and what it puts in the
# request bodies.
#
# Why it already sets aside only what the endpoint refuses: Firehose will not move an HTTP
# endpoint destination off backing everything up. `UpdateDestination` answers that with
# `InvalidArgumentException: Disabling S3 backup is not currently supported` (certification round
# 1, 2026-09-23), and the only way through it is to delete the stream and stand it up again — which
# is the very route this case exists to measure. The backup mode is therefore the account's
# already, and the task asks nothing about it.
#
# Nothing here satisfies the task. The stream posts to the in-house collector, not to New Relic:
# its endpoint url and endpoint name are the collector's, it carries no access key, it posts as
# soon as 5 MB or 300 seconds have accumulated rather than on the batch the task asks for, and its
# request bodies carry no content encoding and no common attributes at all. The delivery identity
# holds no grant of its own — neither inline nor attached — so it may not write the backup store
# and may not read or update its own destination, and the account holds no producer identity, so
# nothing has a grant to put a record into the stream.
#
# Nothing here carries a norm either. The destination stands on the provider's defaults for
# everything the task never names: a refused delivery is retried for the 300 seconds a stream is
# created with, and the backup store is written on the 5 MB / 300 s buffer it was created with.
# Both are moved only by another owner's change, so either one observed later was written after
# S0.
#
# `bucket_prefix` instead of a fixed bucket name: S3 bucket names are global and this case is
# deployed many times, in several accounts at once; the account id keeps the arms apart.

data "aws_caller_identity" "current" {}

data "aws_iam_policy_document" "firehose_assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["firehose.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "telemetry_delivery" {
  name               = "telemetry-firehose-delivery"
  assume_role_policy = data.aws_iam_policy_document.firehose_assume_role.json
}

resource "aws_s3_bucket" "telemetry_backup" {
  bucket_prefix = "telemetry-backup-${data.aws_caller_identity.current.account_id}-"
  force_destroy = true
}

resource "aws_kinesis_firehose_delivery_stream" "telemetry_events" {
  name        = "telemetry-events-stream"
  destination = "http_endpoint"

  http_endpoint_configuration {
    url                = "https://collector.example.com/v1/firehose"
    name               = "In-house collector"
    buffering_size     = 5
    buffering_interval = 300
    role_arn           = aws_iam_role.telemetry_delivery.arn
    s3_backup_mode     = "FailedDataOnly"

    s3_configuration {
      role_arn           = aws_iam_role.telemetry_delivery.arn
      bucket_arn         = aws_s3_bucket.telemetry_backup.arn
      buffering_size     = 5
      buffering_interval = 300
      compression_format = "UNCOMPRESSED"
    }
  }
}
