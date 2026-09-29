# IaC-Eval reference output for row 81 (provider/terraform blocks dropped; the hosted zone
# copied verbatim from initial.tf, where it pre-exists; the record and health-check names
# moved under the zone's own domain so the pair is actually servable).
#
# The clean witness of the task alone: the failover pair lives in the account's zone for
# example53.com, the active side is guarded by an HTTP health check on the active endpoint,
# and the passive side takes over when that check reports unhealthy.

resource "aws_route53_zone" "primary" {
  name    = "example53.com"
  comment = "public zone answering for example53.com"

  tags = {
    Owner       = "orders-team"
    Environment = "production"
  }
}

# Health check for the primary resource
resource "aws_route53_health_check" "primary_health_check" {
  fqdn              = "active.example53.com"
  port              = 80
  type              = "HTTP"
  resource_path     = "/"
  request_interval  = 30
  failure_threshold = 3

  tags = {
    Name = "primary_health_check"
  }
}

# Primary A record with a health check (active endpoint)
resource "aws_route53_record" "primary_record" {
  zone_id         = aws_route53_zone.primary.zone_id
  name            = "www.example53.com"
  type            = "A"
  ttl             = 60
  records         = ["192.0.2.10"]
  set_identifier  = "primary"
  health_check_id = aws_route53_health_check.primary_health_check.id

  failover_routing_policy {
    type = "PRIMARY"
  }
}

# Secondary A record without a health check (passive endpoint)
resource "aws_route53_record" "secondary_record" {
  zone_id        = aws_route53_zone.primary.zone_id
  name           = "www.example53.com"
  type           = "A"
  ttl            = 60
  records        = ["192.0.2.20"]
  set_identifier = "secondary"

  failover_routing_policy {
    type = "SECONDARY"
  }
}
