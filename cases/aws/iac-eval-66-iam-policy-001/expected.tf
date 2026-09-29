# IaC-Eval reference output for row 66 (provider/terraform blocks dropped, the bucket name made
# account-unique), as the clean witness of the main intent with nobody else acting on the
# account: the telemetry stream posting to New Relic's Firehose endpoint on the batch the task
# asks for, with the row's GZIP request encoding and the row's two common attributes, keeping a
# copy only of what New Relic refuses — plus the two grants the row's reference misplaces.
#
# Deviations from the row's reference text, all of them the witness's choice rather than the
# task's:
#   * the names. The row calls the stream `terraform-kinesis-firehose-test-stream`, its role
#     `firehose_http_s3_role` and its bucket `januaryeleventh`; this account already runs the
#     path as `telemetry-events-stream` behind the `telemetry-firehose-delivery` identity, and
#     `januaryeleventh` is a name no account can take twice (S3 names are global, and this case
#     is deployed many times at once), so the store is named for the workload with the account id
#     in it.
#   * the grants. The row puts everything in one policy on the delivery identity, including
#     `firehose:PutRecord` and `firehose:PutRecordBatch` — which a delivery role never calls, and
#     which is the grant the *producer* of the records needs. The witness therefore splits the
#     row's policy where it belongs: the delivery identity gets the store access and the
#     destination-management actions it does use, and the producer identity the row leaves out
#     altogether gets the put-records grant. The row's `firehose:DescribeDestinations` and
#     `firehose:DescribeHttpEndpointDestination` are dropped: neither is an IAM action Firehose
#     declares.
#   * the buffer and the compression on the backup store. The row names 10 MB / 400 s and GZIP;
#     they are carried here because the row names them, but the request asks for neither, so
#     nothing in the account is required to end up on those numbers.
#
# The stream's name, its HTTP endpoint destination, its backup store and its delivery identity
# are the account's already; the task is the destination — the endpoint, the batch, the request
# bodies and what is backed up — and the two identities' grants.
#
# This file is never applied: it is what the account would hold with nobody else in it.

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
    url                = "https://aws-api.newrelic.com/firehose/v1"
    name               = "New Relic"
    access_key         = "my-key"
    buffering_size     = 15
    buffering_interval = 600
    role_arn           = aws_iam_role.telemetry_delivery.arn
    s3_backup_mode     = "FailedDataOnly"

    s3_configuration {
      role_arn           = aws_iam_role.telemetry_delivery.arn
      bucket_arn         = aws_s3_bucket.telemetry_backup.arn
      buffering_size     = 10
      buffering_interval = 400
      compression_format = "GZIP"
    }

    request_configuration {
      content_encoding = "GZIP"

      common_attributes {
        name  = "testname"
        value = "testvalue"
      }

      common_attributes {
        name  = "testname2"
        value = "testvalue2"
      }
    }
  }
}

resource "aws_iam_policy" "telemetry_newrelic_delivery" {
  name        = "telemetry-newrelic-delivery"
  description = "lets the telemetry delivery identity keep its backups and manage its own destination"

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
          aws_s3_bucket.telemetry_backup.arn,
          "${aws_s3_bucket.telemetry_backup.arn}/*",
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "firehose:DescribeDeliveryStream",
          "firehose:ListDeliveryStreams",
          "firehose:UpdateDestination",
        ]
        Resource = "*"
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "telemetry_newrelic_delivery" {
  role       = aws_iam_role.telemetry_delivery.name
  policy_arn = aws_iam_policy.telemetry_newrelic_delivery.arn
}

data "aws_iam_policy_document" "producer_assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "telemetry_producer" {
  name               = "telemetry-events-producer"
  assume_role_policy = data.aws_iam_policy_document.producer_assume_role.json
}

resource "aws_iam_role_policy" "telemetry_producer" {
  name = "telemetry-events-put"
  role = aws_iam_role.telemetry_producer.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "firehose:PutRecord",
        "firehose:PutRecordBatch",
      ]
      Resource = aws_kinesis_firehose_delivery_stream.telemetry_events.arn
    }]
  })
}
