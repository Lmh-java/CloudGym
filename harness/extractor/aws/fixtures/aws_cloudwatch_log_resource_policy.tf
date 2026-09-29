resource "aws_cloudwatch_log_resource_policy" "capability" {
  policy_name = "cloudgym-capability-route53-query-logging"
  policy_document = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "Route53QueryLogging"
      Effect    = "Allow"
      Principal = { Service = "route53.amazonaws.com" }
      Action    = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource  = "arn:aws:logs:*:*:log-group:/aws/route53/cloudgym-capability*"
    }]
  })
}
