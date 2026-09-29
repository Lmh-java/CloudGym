resource "aws_iam_role" "dependency" {
  name_prefix = "cloudgym-capability-"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "kinesisanalytics.amazonaws.com" }
    }]
  })
}

resource "aws_kinesisanalyticsv2_application" "capability" {
  # no name_prefix; a leaked previous run fails the apply visibly.
  name                   = "cloudgym-capability-flink"
  runtime_environment    = "FLINK-1_20"
  service_execution_role = aws_iam_role.dependency.arn

  tags = {
    Name = "cloudgym-capability"
  }
}
