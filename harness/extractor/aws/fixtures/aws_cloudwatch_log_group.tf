resource "aws_cloudwatch_log_group" "capability" {
  name_prefix       = "cloudgym-capability-"
  retention_in_days = 1
}
