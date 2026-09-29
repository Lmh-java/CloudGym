# IaC-Eval reference output for row 84 (provider/terraform blocks dropped; the pre-existing
# hosted zone copied verbatim from initial.tf). The clean witness of the task with nobody else
# around: service.example53.com answered by a latency-routed pair of A records, one member per
# region, so a caller is sent to whichever endpoint is quickest to reach from it.

resource "aws_route53_zone" "primary" {
  name = "example53.com"
}

# Record for the endpoint in the US East region
resource "aws_route53_record" "us_east_record" {
  zone_id = aws_route53_zone.primary.zone_id
  name    = "service.example53.com"
  type    = "A"
  ttl     = "60"
  records = ["192.0.2.101"]

  set_identifier = "US East N. Virginia"

  latency_routing_policy {
    region = "us-east-1"
  }
}

# Record for the endpoint in the EU region
resource "aws_route53_record" "eu_central_record" {
  zone_id = aws_route53_zone.primary.zone_id
  name    = "service.example53.com"
  type    = "A"
  ttl     = "60"
  records = ["192.0.2.102"]

  set_identifier = "EU Frankfurt"

  latency_routing_policy {
    region = "eu-central-1"
  }
}
