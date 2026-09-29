# IaC-Eval reference output for row 82 (provider/terraform blocks dropped; the hosted zone
# copied verbatim from initial.tf, where it pre-exists; the health checks carry the names the
# request dictates and the record sets sit on the zone's own apex so the pair is servable).
#
# The clean witness of the task alone: with nobody else acting on the account nothing is
# published for the domain's two sides, so the pair answers the addresses of the endpoints the
# request's own naming implies, each side guarded by its own HTTP check on a fully-qualified
# name. This file is never applied.

resource "aws_route53_zone" "main" {
  name    = "example53.com"
  comment = "the account's public zone for example53.com"

  tags = {
    Owner       = "storefront-team"
    Environment = "production"
  }
}

resource "aws_route53_health_check" "primary_health_check" {
  fqdn              = "primary.example53.com"
  port              = 80
  type              = "HTTP"
  resource_path     = "/"
  request_interval  = 30
  failure_threshold = 3

  tags = {
    Name = "primary_health_check"
  }
}

resource "aws_route53_record" "primary_record" {
  zone_id         = aws_route53_zone.main.zone_id
  name            = "example53.com"
  type            = "A"
  ttl             = 60
  records         = ["192.0.2.101"]
  set_identifier  = "primary-endpoint"
  health_check_id = aws_route53_health_check.primary_health_check.id

  failover_routing_policy {
    type = "PRIMARY"
  }
}

resource "aws_route53_health_check" "secondary_health_check" {
  fqdn              = "secondary.example53.com"
  port              = 80
  type              = "HTTP"
  resource_path     = "/"
  request_interval  = 30
  failure_threshold = 3

  tags = {
    Name = "secondary_health_check"
  }
}

resource "aws_route53_record" "secondary_record" {
  zone_id         = aws_route53_zone.main.zone_id
  name            = "example53.com"
  type            = "A"
  ttl             = 60
  records         = ["192.0.2.102"]
  set_identifier  = "secondary-endpoint"
  health_check_id = aws_route53_health_check.secondary_health_check.id

  failover_routing_policy {
    type = "SECONDARY"
  }
}
