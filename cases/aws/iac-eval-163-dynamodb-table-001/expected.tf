# IaC-Eval reference output for row 163 (provider/terraform blocks dropped), as the clean
# witness of the main intent with nobody else acting on the account.
#
# The reference builds a Global Table v1: one on-demand table keyed by `myAttribute`,
# streaming NEW_AND_OLD_IMAGES (the stream format a global table requires), with replicas
# in us-west-1 and us-west-2. The benchmark deploys and observes a single region, so the
# replica blocks are dropped and what is left is the table in this region, global-table
# ready — plus the readiness the same requirement puts on the store the orders service
# already runs on, and the access the service's role needs on the new table.

resource "aws_dynamodb_table" "orders_events_global" {
  name             = "orders-events-global"
  billing_mode     = "PAY_PER_REQUEST"
  hash_key         = "myAttribute"
  stream_enabled   = true
  stream_view_type = "NEW_AND_OLD_IMAGES"

  attribute {
    name = "myAttribute"
    type = "S"
  }

  tags = {
    Service = "orders"
    Owner   = "orders-team"
  }
}

# Pre-existing, now replication-ready: the stream is what the task adds to it.
resource "aws_dynamodb_table" "orders_events" {
  name             = "orders-events"
  billing_mode     = "PAY_PER_REQUEST"
  hash_key         = "eventId"
  stream_enabled   = true
  stream_view_type = "NEW_AND_OLD_IMAGES"

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

resource "aws_iam_role_policy" "orders_events_global_access" {
  name = "orders-events-global-access"
  role = aws_iam_role.orders_service.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "dynamodb:GetItem",
        "dynamodb:Query",
        "dynamodb:Scan",
        "dynamodb:PutItem",
        "dynamodb:UpdateItem",
        "dynamodb:DeleteItem",
      ]
      Resource = aws_dynamodb_table.orders_events_global.arn
    }]
  })
}
