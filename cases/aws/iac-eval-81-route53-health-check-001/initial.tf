# Pre-existing: the account's public hosted zone for example53.com — the zone that
# already answers for the domain, carrying the application's attribution and a comment
# that says what it is.
#
# Nothing of the task exists at S0. The zone holds only its own NS and SOA records, so
# no name under example53.com is answered yet; the account holds no Route 53 health
# check at all, and no failover record set anywhere. The active-passive pair the task
# asks for is absent in both directions.

resource "aws_route53_zone" "primary" {
  name    = "example53.com"
  comment = "public zone answering for example53.com"

  tags = {
    Owner       = "orders-team"
    Environment = "production"
  }
}
