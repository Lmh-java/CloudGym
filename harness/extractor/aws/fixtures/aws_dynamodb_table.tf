resource "aws_dynamodb_table" "capability" {
  # aws_dynamodb_table has no name_prefix; a leaked previous run fails the apply visibly.
  name         = "cloudgym-capability-table"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"

  attribute {
    name = "pk"
    type = "S"
  }
}
