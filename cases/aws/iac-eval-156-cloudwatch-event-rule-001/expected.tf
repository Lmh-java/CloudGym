# IaC-Eval reference output for row 156 (provider/terraform blocks dropped; the archive source
# inlined; the function and its execution role named as they stand in initial.tf). Never applied:
# it is the clean witness of the task with nobody else acting on the account.

resource "aws_cloudwatch_event_rule" "scan_ami" {
  name          = "EC2CreateImageEvent"
  description   = "EC2 Create Image Event..."
  role_arn      = aws_iam_role.scan.arn
  event_pattern = <<EOF
{
  "source": ["aws.ec2"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["ec2.amazonaws.com"],
    "eventName": ["CreateImage"]
  }
}
EOF
}

resource "aws_cloudwatch_event_target" "scan_ami_lambda_function" {
  rule = aws_cloudwatch_event_rule.scan_ami.name
  arn  = aws_lambda_function.scan.arn
}

data "archive_file" "lambda-func" {
  type        = "zip"
  output_path = "${path.module}/lambda_func.zip"
  source {
    filename = "lambda_func.py"
    content  = "def handler(event, context):\n    return {\"ok\": True}\n"
  }
}

resource "aws_lambda_function" "scan" {
  function_name    = "test_lambda"
  role             = aws_iam_role.scan.arn
  filename         = data.archive_file.lambda-func.output_path
  source_code_hash = data.archive_file.lambda-func.output_base64sha256
  handler          = "lambda_func.handler"
  runtime          = "python3.12"
}

resource "aws_lambda_permission" "scan" {
  function_name = aws_lambda_function.scan.function_name
  action        = "lambda:InvokeFunction"
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.scan_ami.arn
}

data "aws_iam_policy_document" "scan_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type = "Service"
      identifiers = [
        "lambda.amazonaws.com",
        "events.amazonaws.com"
      ]
    }
  }
}

resource "aws_iam_role" "scan" {
  name               = "image_scan_role"
  assume_role_policy = data.aws_iam_policy_document.scan_assume_role.json
}

resource "aws_iam_role_policy_attachment" "scan" {
  role       = aws_iam_role.scan.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}
