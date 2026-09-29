# IaC-Eval reference output for row 223 (provider/terraform blocks dropped, the placeholder
# table name resolved to the orders service's naming space, external inputs inlined). The
# witness of the task alone, with no other principal acting: the new order-event table with
# point-in-time recovery enabled, the same recovery setting turned on for the service's
# pre-existing table, and the writer identity for the new table.

resource "aws_dynamodb_table" "order_events" {
  name         = "orders-app-order-events"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "event_id"

  attribute {
    name = "event_id"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  tags = {
    Service = "orders"
    Owner   = "orders-team"
  }
}

resource "aws_dynamodb_table" "orders" {
  name         = "orders-app-orders"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "order_id"

  attribute {
    name = "order_id"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  tags = {
    Service = "orders"
    Owner   = "orders-team"
  }
}

data "aws_iam_policy_document" "order_events_writer_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "order_events_writer" {
  name               = "orders-app-order-events-writer"
  assume_role_policy = data.aws_iam_policy_document.order_events_writer_assume_role.json

  tags = {
    Service = "orders"
    Owner   = "orders-team"
  }
}

resource "aws_iam_role_policy" "order_events_writer" {
  name = "order-events-write"
  role = aws_iam_role.order_events_writer.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:Query",
        ]
        Resource = aws_dynamodb_table.order_events.arn
      },
    ]
  })
}
