# Pre-existing: the execution identity the application's Lambda functions run as. The
# account provisions the role and its assume-role policy document ahead of the code, so a
# function stood up here already has an identity to run as.
#
# Nothing of the task exists yet: at S0 the account holds no Lambda function at all — no
# function carries a runtime, an entry point, a health baseline or telemetry settings — so
# nothing here satisfies the task or already carries a norm.

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
