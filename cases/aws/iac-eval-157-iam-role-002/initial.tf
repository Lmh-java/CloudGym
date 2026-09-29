# Pre-existing: the account's pool of Lambda execution identities. Every execution
# identity in this account is provisioned centrally and carries the pool's marking —
# `ManagedBy = identity-platform` — plus a `Workload` tag recording which workload
# holds it; `unassigned` means the identity is free for the next workload to take.
#
# At S0 the pool holds exactly one identity, `lambda-exec-pool-1`, and it is free: no
# workload holds it, nothing is attached to it, and there is no Lambda function in the
# account at all. Nothing here runs `lambda.js`, and no second pooled identity exists.

data "aws_iam_policy_document" "assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "pool_1" {
  name               = "lambda-exec-pool-1"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json
  description        = "Pooled Lambda execution identity"

  tags = {
    ManagedBy = "identity-platform"
    Workload  = "unassigned"
  }
}
