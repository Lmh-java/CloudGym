resource "aws_api_gateway_rest_api" "capability" {
  name        = "cloudgym-capability"
  description = "CloudGym extractor capability check"

  endpoint_configuration {
    types = ["REGIONAL"]
  }
}
