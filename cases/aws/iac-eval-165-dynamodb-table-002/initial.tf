# Pre-existing: the tournament service's high-score store, as it stands before anyone asks for
# tournament-scale throughput. `tournament-scores` is the live store — keyed on `UserId` with
# `GameTitle` as its range key, reachable by title through the `GameTitleIndex` lookup path its
# readers already run on, and carrying the record every resource in this account carries: the
# service that owns it and the team accountable for it.
#
# It is still standing at the throughput it was prototyped on, and nothing here satisfies the
# task. The store is at read 5 / write 5, not read 20 / write 20; its time-to-live
# specification is off, as it is on every table by default; it does not record an environment;
# and the account holds no `tournament-service` role, so nothing has a grant on the store at
# all. `GameTitleIndex` is the one thing the task names that the store already carries — it is
# the path its readers run on today — so the task's work on that path is to leave it standing
# while the throughput, the expiry and the environment record change around it.

resource "aws_dynamodb_table" "tournament_scores" {
  name           = "tournament-scores"
  billing_mode   = "PROVISIONED"
  read_capacity  = 5
  write_capacity = 5
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

  attribute {
    name = "TopScore"
    type = "N"
  }

  global_secondary_index {
    name               = "GameTitleIndex"
    hash_key           = "GameTitle"
    range_key          = "TopScore"
    write_capacity     = 10
    read_capacity      = 10
    projection_type    = "INCLUDE"
    non_key_attributes = ["UserId"]
  }

  tags = {
    Service = "tournament"
    Owner   = "tournament-team"
  }
}
