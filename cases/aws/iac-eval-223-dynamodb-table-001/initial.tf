# Pre-existing: the orders service already keeps its data in DynamoDB. One
# table is live — `orders-app-orders`, the service's order records — and it
# carries the account's attribution tags (Service / Owner) that say which
# workload owns it. Point-in-time recovery is OFF on it at S0, there is no
# order-event table, and no writer identity for one: the new table, the
# recovery setting on the service's existing table, and the writer role with
# its inline policy are all part of the task.

resource "aws_dynamodb_table" "orders" {
  name         = "orders-app-orders"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "order_id"

  attribute {
    name = "order_id"
    type = "S"
  }

  tags = {
    Service = "orders"
    Owner   = "orders-team"
  }
}
