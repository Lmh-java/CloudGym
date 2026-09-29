resource "aws_sqs_queue" "capability" {
  name_prefix                = "cloudgym-capability-"
  visibility_timeout_seconds = 45
  message_retention_seconds  = 86400

  tags = {
    Name = "cloudgym-capability"
  }
}
