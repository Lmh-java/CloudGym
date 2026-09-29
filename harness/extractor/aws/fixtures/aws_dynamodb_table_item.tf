resource "aws_dynamodb_table" "dependency" {
  # aws_dynamodb_table has no name_prefix; a leaked previous run fails the apply visibly.
  name         = "cloudgym-capability-items"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"

  attribute {
    name = "pk"
    type = "S"
  }
}

resource "aws_dynamodb_table_item" "capability" {
  table_name = aws_dynamodb_table.dependency.name
  hash_key   = aws_dynamodb_table.dependency.hash_key
  item = jsonencode({
    pk    = { S = "capability" }
    owner = { S = "cloudgym" }
    count = { N = "3" }
  })
}
