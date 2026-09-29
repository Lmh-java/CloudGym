# Pre-existing: the ledger service as it stands before anyone asks for multi-region.
#
# `ledger-entries` is the service's live entry store — on-demand, keyed by `entryId`, and
# with no stream at all, so nothing about it is ready to be replicated yet. `ledger-service`
# is the role the service runs as; it holds no policy on any table (granting it access to
# the new store is part of the task).
#
# Every resource the ledger service owns records that ownership the same way: a `Service`
# tag naming the workload and an `Owner` tag naming the team accountable for it. Those two
# marks are the account's owner record, and the new store has to end up carrying them too.
#
# Nothing here satisfies the task: there is no `ledger-entries-global` table, no stream on
# `ledger-entries`, and no policy on the role. Nothing here carries a catalogue reference,
# a feed review mark, a restore window or a freeze window either.

resource "aws_dynamodb_table" "ledger_entries" {
  name         = "ledger-entries"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "entryId"

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
