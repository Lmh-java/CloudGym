# IaC-Eval reference output for row 117 (provider/terraform blocks dropped; the pre-existing
# store copied verbatim from initial.tf). The clean witness of the task with nobody else around:
# a topic for the store's object events, its access policy admitting the S3 service only for
# events whose source is that store, and the store's notification for created objects whose name
# ends in `.log`.
#
# One deviation from the row's reference text, forced by what S3 accepts: the row names the
# bucket `your-bucket-name`, a placeholder in a global namespace no account can actually take, so
# the store is the account's own `app-logs-` store — the one the task is asked against — exactly
# as initial.tf declares it.

data "aws_caller_identity" "current" {}

resource "aws_s3_bucket" "bucket" {
  bucket_prefix = "app-logs-${data.aws_caller_identity.current.account_id}-"
  force_destroy = true

  tags = {
    Store = "app-logs"
    Owner = "orders-team"
  }
}

data "aws_iam_policy_document" "topic" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["s3.amazonaws.com"]
    }

    actions   = ["SNS:Publish"]
    resources = ["arn:aws:sns:*:*:s3-event-notification-topic"]

    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = [aws_s3_bucket.bucket.arn]
    }
  }
}

resource "aws_sns_topic" "topic" {
  name   = "s3-event-notification-topic"
  policy = data.aws_iam_policy_document.topic.json
}

resource "aws_s3_bucket_notification" "bucket_notification" {
  bucket = aws_s3_bucket.bucket.id

  topic {
    topic_arn     = aws_sns_topic.topic.arn
    events        = ["s3:ObjectCreated:*"]
    filter_suffix = ".log"
  }
}
