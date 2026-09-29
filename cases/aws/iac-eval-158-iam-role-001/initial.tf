# Pre-existing: the execution identity the application's Lambda functions run as. The account
# provisions the role and its assume-role policy document ahead of the code, so a function
# stood up here already has an identity to run as.
#
# Nothing of the task exists yet, and nothing here carries a norm: at S0 the account holds no
# Lambda function at all, no second execution identity and no successor to this one, no
# customer managed grant of any kind, and `iam_for_lambda` carries no attached policy, no
# description and no marking that says whether it is the one in service or one the account has
# moved on from.

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

resource "aws_iam_role" "iam_for_lambda" {
  name               = "iam_for_lambda"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json
}
