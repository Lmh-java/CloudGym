resource "aws_iam_role" "dependency" {
  name_prefix = "cloudgym-capability-"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lexv2.amazonaws.com" }
    }]
  })
}

resource "aws_lexv2models_bot" "capability" {
  name                        = "cloudgym-capability-bot"
  role_arn                    = aws_iam_role.dependency.arn
  idle_session_ttl_in_seconds = 300

  data_privacy {
    child_directed = false
  }

  tags = {
    Name = "cloudgym-capability"
  }
}
