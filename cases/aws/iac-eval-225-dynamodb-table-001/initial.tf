# Pre-existing: the game-scores workload as it stands before anyone asks for tournament
# sizing.
#
# `GameSessions` is the one store the workload owns here. It is provisioned, but at the
# smallest sizing there is (1 read unit, 1 write unit) — enough for the off season and
# nothing like what a tournament needs. `game-scores-service` is the role the workload runs
# as; it holds no policy on any store (granting it access to the new store is part of the
# task).
#
# Attribution is how this account records what a store belongs to: a `Service` tag naming
# the workload and an `Owner` tag naming the team accountable for it. At S0 the two ways of
# reading "the stores the game-scores workload owns" — the attribution a store carries, and
# the family its name sits in — agree, and both pick out exactly this one table.
#
# Nothing here satisfies the task: there is no `GameScores` table, the store the workload
# owns is not on the sizing the task asks for, and the role holds no policy.

resource "aws_dynamodb_table" "game_sessions" {
  name           = "GameSessions"
  billing_mode   = "PROVISIONED"
  read_capacity  = 1
  write_capacity = 1
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
