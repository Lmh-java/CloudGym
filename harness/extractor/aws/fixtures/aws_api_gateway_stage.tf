resource "aws_api_gateway_rest_api" "dependency" {
  name = "cloudgym-capability"

  endpoint_configuration {
    types = ["REGIONAL"]
  }
}

resource "aws_api_gateway_resource" "dependency" {
  rest_api_id = aws_api_gateway_rest_api.dependency.id
  parent_id   = aws_api_gateway_rest_api.dependency.root_resource_id
  path_part   = "capability"
}

resource "aws_api_gateway_method" "dependency" {
  rest_api_id   = aws_api_gateway_rest_api.dependency.id
  resource_id   = aws_api_gateway_resource.dependency.id
  http_method   = "GET"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "dependency" {
  rest_api_id = aws_api_gateway_rest_api.dependency.id
  resource_id = aws_api_gateway_resource.dependency.id
  http_method = aws_api_gateway_method.dependency.http_method
  type        = "MOCK"
}

resource "aws_api_gateway_deployment" "dependency" {
  rest_api_id = aws_api_gateway_rest_api.dependency.id

  depends_on = [aws_api_gateway_integration.dependency]
}

resource "aws_api_gateway_stage" "capability" {
  rest_api_id   = aws_api_gateway_rest_api.dependency.id
  deployment_id = aws_api_gateway_deployment.dependency.id
  stage_name    = "capability"
  description   = "CloudGym extractor capability check"

  variables = {
    owner = "cloudgym"
  }
}
