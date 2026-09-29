# Pre-existing: the orders service as it stands before anyone asks for multi-region.
#
# `orders-events` is the service's live event store — on-demand, keyed by `eventId`, and
# with no stream at all, so nothing about it is ready to be replicated yet. `orders-service`
# is the role the service runs as; it holds no policy on any table (granting it access to
# the new store is part of the task).
#
# Every data store in this account records the service that owns it in a `Service` tag:
# that mark, not the table's name, is what says which workload a table belongs to.
# Nothing here satisfies the task: there is no `orders-events-global` table, no stream on
# any table, and no policy on the role.

resource "aws_dynamodb_table" "orders_events" {
  name         = "orders-events"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "eventId"

  attribute {
    name = "eventId"
    type = "S"
  }

  tags = {
    Service = "orders"
    Owner   = "orders-team"
  }
}

data "aws_iam_policy_document" "orders_service_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "orders_service" {
  name               = "orders-service"
  assume_role_policy = data.aws_iam_policy_document.orders_service_assume.json

  tags = {
    Service = "orders"
    Owner   = "orders-team"
  }
}
