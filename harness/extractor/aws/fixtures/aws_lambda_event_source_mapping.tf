resource "aws_iam_role" "dependency" {
  name_prefix = "cloudgym-capability-"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

data "archive_file" "dependency" {
  type        = "zip"
  output_path = "${path.module}/capability.zip"
  source {
    filename = "handler.py"
    content  = "def handler(event, context):\n    return {\"ok\": True}\n"
  }
}

resource "aws_iam_role_policy_attachment" "dependency" {
  role       = aws_iam_role.dependency.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaDynamoDBExecutionRole"
}

resource "aws_dynamodb_table" "dependency" {
  # aws_dynamodb_table has no name_prefix; a leaked previous run fails the apply visibly.
  name             = "cloudgym-capability-esm"
  billing_mode     = "PAY_PER_REQUEST"
  hash_key         = "pk"
  stream_enabled   = true
  stream_view_type = "NEW_IMAGE"

  attribute {
    name = "pk"
    type = "S"
  }
}

resource "aws_lambda_function" "dependency" {
  function_name    = "cloudgym-capability-esm-fn"
  role             = aws_iam_role.dependency.arn
  filename         = data.archive_file.dependency.output_path
  source_code_hash = data.archive_file.dependency.output_base64sha256
  handler          = "handler.handler"
  runtime          = "python3.12"
}

resource "aws_lambda_event_source_mapping" "capability" {
  event_source_arn  = aws_dynamodb_table.dependency.stream_arn
  function_name     = aws_lambda_function.dependency.arn
  starting_position = "LATEST"
  batch_size        = 10

  depends_on = [aws_iam_role_policy_attachment.dependency]
}
