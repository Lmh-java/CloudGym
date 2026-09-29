resource "aws_cloudwatch_log_group" "dependency" {
  name_prefix       = "/aws/route53/cloudgym-capability-"
  retention_in_days = 1
}

resource "aws_cloudwatch_log_resource_policy" "dependency" {
  policy_name = "cloudgym-capability-query-log-fixture"
  policy_document = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "route53.amazonaws.com" }
      Action    = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource  = "arn:aws:logs:*:*:log-group:/aws/route53/*"
    }]
  })
}

resource "aws_route53_zone" "capability" {
  name    = "cloudgym-capability-querylog.test"
  comment = "cloudgym extractor capability fixture"
}

resource "aws_route53_query_log" "capability" {
  zone_id                  = aws_route53_zone.capability.zone_id
  cloudwatch_log_group_arn = aws_cloudwatch_log_group.dependency.arn

  depends_on = [aws_cloudwatch_log_resource_policy.dependency]
}
