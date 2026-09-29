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

# A deployment needs at least one integrated method to exist first.
resource "aws_api_gateway_deployment" "capability" {
  rest_api_id = aws_api_gateway_rest_api.dependency.id
  description = "CloudGym extractor capability check"

  depends_on = [aws_api_gateway_integration.dependency]
}
