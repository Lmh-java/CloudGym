resource "aws_api_gateway_rest_api" "dependency" {
  name = "cloudgym-capability"

  endpoint_configuration {
    types = ["REGIONAL"]
  }
}

resource "aws_api_gateway_resource" "capability" {
  rest_api_id = aws_api_gateway_rest_api.dependency.id
  parent_id   = aws_api_gateway_rest_api.dependency.root_resource_id
  path_part   = "capability"
}
