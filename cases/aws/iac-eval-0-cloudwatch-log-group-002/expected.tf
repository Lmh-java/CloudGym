# IaC-Eval row 0, reference output rewritten against the pre-existing DNS state
# (provider/terraform blocks dropped; the storefront hosted zone already exists and is carried
# through unchanged).
#
# The clean witness of the main intent with nobody else acting: a log group named for the zone,
# an account-level CloudWatch Logs resource policy that lets the Route 53 service create log
# streams and put log events in it, and the zone's query logging configuration delivering there.

resource "aws_route53_zone" "primary" {
  name    = "example53.com"
  comment = "storefront public zone"

  tags = {
    Name  = "example53.com"
    Owner = "dns-platform"
  }
}

resource "aws_cloudwatch_log_group" "aws_route53_example_com" {
  name              = "/aws/route53/${aws_route53_zone.primary.name}"
  retention_in_days = 30
}

# CloudWatch log resource policy allowing Route 53 to write logs to log groups
# under /aws/route53/*.

data "aws_iam_policy_document" "route53-query-logging-policy" {
  statement {
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]

    resources = ["arn:aws:logs:*:*:log-group:/aws/route53/*"]

    principals {
      identifiers = ["route53.amazonaws.com"]
      type        = "Service"
    }
  }
}

resource "aws_cloudwatch_log_resource_policy" "route53-query-logging-policy" {
  policy_document = data.aws_iam_policy_document.route53-query-logging-policy.json
  policy_name     = "route53-query-logging-policy"
}

resource "aws_route53_query_log" "example_com" {
  depends_on = [aws_cloudwatch_log_resource_policy.route53-query-logging-policy]

  cloudwatch_log_group_arn = aws_cloudwatch_log_group.aws_route53_example_com.arn
  zone_id                  = aws_route53_zone.primary.zone_id
}
