# Pre-existing: the execution identity this account's Lambda workers run as. Its markings say
# what the identity is for and that the platform keeps it for the whole account, so it is what
# the account keeps as the execution identity for a Lambda workload.
#
# Nothing of the task exists yet: at S0 the account holds no Lambda function at all — no worker
# for this workload, no other application's worker, no worker under migration — and the identity
# carries no permissions of any kind. So nothing here satisfies the task, and nothing here
# already carries a norm another principal is about to establish.

data "aws_iam_policy_document" "assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "iam_for_lambda" {
  name               = "iam_for_lambda"
  description        = "the execution identity this account's Lambda workers run as"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json

  tags = {
    Purpose = "lambda-execution"
    Scope   = "account"
    Owner   = "platform"
  }
}
