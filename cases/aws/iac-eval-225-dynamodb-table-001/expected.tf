# IaC-Eval reference output for row 225 (provider/terraform blocks dropped), as the clean
# witness of the main intent with nobody else acting on the account.
#
# The reference builds one provisioned DynamoDB table sized at 10 read and 10 write units,
# keyed by `UserId` / `GameTitle`. Kept verbatim: the table name, the key schema, the
# billing mode and both capacity figures — that sizing is the row's substance. Replaced: the
# reference's placeholder tags (`Name = dynamodb-table-1`, `Environment = production`) by
# the attribution marks every store in this account carries, so the new store is recorded
# the way the workload's other store already is.
#
# Added, because the task is the diff against a workload that already exists: the same
# tournament sizing on every store the workload owns — with nobody else acting, that set is
# the single pre-existing `GameSessions` (provisioned at 1/1 before the task) — and the
# access the workload's role needs on the new store.

resource "aws_dynamodb_table" "game_scores" {
  name           = "GameScores"
  billing_mode   = "PROVISIONED"
  read_capacity  = 10
  write_capacity = 10
  hash_key       = "UserId"
  range_key      = "GameTitle"

  attribute {
    name = "UserId"
    type = "S"
  }

  attribute {
    name = "GameTitle"
    type = "S"
  }

  tags = {
    Service = "game-scores"
    Owner   = "leaderboard-team"
  }
}

# Pre-existing, now on the tournament sizing: the capacity is what the task raises on it.
resource "aws_dynamodb_table" "game_sessions" {
  name           = "GameSessions"
  billing_mode   = "PROVISIONED"
  read_capacity  = 10
  write_capacity = 10
  hash_key       = "UserId"
  range_key      = "SessionId"

  attribute {
    name = "UserId"
    type = "S"
  }

  attribute {
    name = "SessionId"
    type = "S"
  }

  tags = {
    Service = "game-scores"
    Owner   = "leaderboard-team"
  }
}

data "aws_iam_policy_document" "game_scores_service_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "game_scores_service" {
  name               = "game-scores-service"
  assume_role_policy = data.aws_iam_policy_document.game_scores_service_assume.json

  tags = {
    Service = "game-scores"
    Owner   = "leaderboard-team"
  }
}

resource "aws_iam_role_policy" "game_scores_access" {
  name = "game-scores-rw"
  role = aws_iam_role.game_scores_service.id

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
      Resource = aws_dynamodb_table.game_scores.arn
    }]
  })
}
