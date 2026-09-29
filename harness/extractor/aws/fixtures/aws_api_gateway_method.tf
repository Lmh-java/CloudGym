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

resource "aws_api_gateway_method" "capability" {
  rest_api_id   = aws_api_gateway_rest_api.dependency.id
  resource_id   = aws_api_gateway_resource.dependency.id
  http_method   = "GET"
  authorization = "NONE"
}
