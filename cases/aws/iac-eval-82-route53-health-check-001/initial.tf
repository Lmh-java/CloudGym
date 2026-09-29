# Pre-existing: the account's public hosted zone for example53.com — the zone that
# already answers for the domain, carrying the application's attribution and a comment
# that says what it is.
#
# Nothing of the task exists at S0. The zone holds only its own NS and SOA records, so
# no name under example53.com is answered yet: the apex carries no A answer at all, the
# account publishes no endpoint for the domain's live or standby side, holds no Route 53
# health check, and no failover record set anywhere.

resource "aws_route53_zone" "main" {
  name    = "example53.com"
  comment = "the account's public zone for example53.com"

  tags = {
    Owner       = "storefront-team"
    Environment = "production"
  }
}
