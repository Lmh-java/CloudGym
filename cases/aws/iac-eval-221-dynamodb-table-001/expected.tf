# IaC-Eval reference output for row 221 (provider/terraform blocks dropped), as the clean
# witness of the main intent with nobody else acting on the account.
#
# The reference builds a Global Table v1: one on-demand table with a string hash key,
# streaming NEW_AND_OLD_IMAGES (the stream format a global table requires), with replicas in
# two other regions. The benchmark deploys and observes a single region, so the replica
# blocks are dropped and what is left is the table in this region, global-table ready — plus
# the readiness the same requirement puts on the store the ledger service already runs on,
# and the access the service's role needs on the new store. The reference's placeholder
# names (`example`, `TestTableHashKey`/`TEST_KEY`, which do not even agree with each other)
# are replaced by the names the utterance gives.

resource "aws_dynamodb_table" "ledger_entries_global" {
  name             = "ledger-entries-global"
  billing_mode     = "PAY_PER_REQUEST"
  hash_key         = "entryId"
  stream_enabled   = true
  stream_view_type = "NEW_AND_OLD_IMAGES"

  attribute {
    name = "entryId"
    type = "S"
  }

  tags = {
    Service = "ledger"
    Owner   = "ledger-platform"
  }
}

# Pre-existing, now replication-ready: the stream is what the task adds to it.
resource "aws_dynamodb_table" "ledger_entries" {
  name             = "ledger-entries"
  billing_mode     = "PAY_PER_REQUEST"
  hash_key         = "entryId"
  stream_enabled   = true
  stream_view_type = "NEW_AND_OLD_IMAGES"

  attribute {
    name = "entryId"
    type = "S"
  }

  tags = {
    Service = "ledger"
    Owner   = "ledger-platform"
  }
}

data "aws_iam_policy_document" "ledger_service_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "ledger_service" {
  name               = "ledger-service"
  assume_role_policy = data.aws_iam_policy_document.ledger_service_assume.json

  tags = {
    Service = "ledger"
    Owner   = "ledger-platform"
  }
}

resource "aws_iam_role_policy" "ledger_entries_global_access" {
  name = "ledger-entries-global-rw"
  role = aws_iam_role.ledger_service.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "dynamodb:GetItem",
        "dynamodb:BatchGetItem",
        "dynamodb:Query",
        "dynamodb:Scan",
        "dynamodb:PutItem",
        "dynamodb:UpdateItem",
        "dynamodb:DeleteItem",
        "dynamodb:BatchWriteItem",
      ]
      Resource = aws_dynamodb_table.ledger_entries_global.arn
    }]
  })
}
