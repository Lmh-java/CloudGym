# Pre-existing: the execution identity this account runs its Lambda functions as.
# Its markings say that it is one of the account's Lambda execution identities and that it
# is the one in service, so it is what the account currently designates for its Lambda
# functions.
#
# Nothing of the task exists yet: at S0 the account holds no Lambda function, no second
# Lambda execution identity, no retired or successor execution identity, no sibling team's
# copy, and the designated identity carries no permissions of any kind — so nothing here
# satisfies the task or already carries a norm.

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
  description        = "the account's Lambda execution identity"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json

  tags = {
    Purpose = "lambda-execution"
    Status  = "current"
    Owner   = "platform"
  }
}
