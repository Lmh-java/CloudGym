# Pre-existing: the account's public hosted zone for example53.com — the zone that already
# answers for the domain, carrying the application's attribution and a comment that says
# what it is.
#
# Nothing of the task exists at S0. The zone holds only its own NS and SOA records, so no
# name under example53.com is answered yet: nothing answers www.app.example53.com, nothing
# answers the active endpoint active.app.example53.com, and the account holds no Route 53
# health check at all and no failover record set anywhere. The application namespace
# app.example53.com has no zone of its own and no handover to one, so at S0 the zone below
# is the only place a name under the domain could be answered.

resource "aws_route53_zone" "primary" {
  name    = "example53.com"
  comment = "public zone answering for example53.com"

  tags = {
    Owner       = "orders-team"
    Environment = "production"
  }
}
