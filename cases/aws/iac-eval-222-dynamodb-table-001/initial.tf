# Pre-existing: the checkout service as it stands before anyone asks for multi-region.
#
# `checkout-events` is the service's live event store — on demand, keyed by `eventId`, with no
# stream at all, so nothing about it is ready to be replicated yet. It is kept the way this
# account keeps event data: on the storage class it was created with, with no expiry on its
# items, and carrying the records every data store here carries — the service that owns it,
# what it holds, and how the data is classified. `checkout-service` is the role the service
# runs as; it holds no policy on any table.
#
# Nothing here satisfies the task: there is no `checkout-events-global` table, no stream on any
# table, and no grant on the role.

resource "aws_dynamodb_table" "checkout_events" {
  name         = "checkout-events"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "eventId"

  attribute {
    name = "eventId"
    type = "S"
  }

  tags = {
    Service        = "checkout"
    Store          = "events"
    Classification = "internal"
  }
}

data "aws_iam_policy_document" "checkout_service_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "checkout_service" {
  name               = "checkout-service"
  assume_role_policy = data.aws_iam_policy_document.checkout_service_assume.json

  tags = {
    Service = "checkout"
    Owner   = "checkout-team"
  }
}
