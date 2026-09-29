# Pre-existing: the arcade game service's identity, as it stands before anyone asks for a
# scores store. `arcade-service` is the role the service runs as; it holds no grant on any
# data store, and it carries the record every resource in this account carries — the service
# that owns it.
#
# Nothing else is here: at S0 the account holds no DynamoDB table at all, so the service has
# no scores store, nothing is provisioned at any capacity, no secondary index exists, and the
# role has no policy attached. Every table this case ever sees is written during the run.

data "aws_iam_policy_document" "arcade_service_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "arcade_service" {
  name               = "arcade-service"
  assume_role_policy = data.aws_iam_policy_document.arcade_service_assume.json

  tags = {
    Service = "arcade"
    Owner   = "arcade-team"
  }
}
