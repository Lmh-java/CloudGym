resource "aws_sns_topic" "capability" {
  name_prefix  = "cloudgym-capability-"
  display_name = "CloudGym capability check"
}
