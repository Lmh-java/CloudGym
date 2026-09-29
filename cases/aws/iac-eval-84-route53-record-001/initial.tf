# Pre-existing: the public domain the account publishes under — the Route 53
# hosted zone `primary` for example53.com. At S0 the zone holds only the NS and
# SOA entries Route 53 mints with it: nothing answers for service.example53.com,
# no record below the apex exists at all, and no record anywhere carries a
# routing policy. The endpoint records are the task.

resource "aws_route53_zone" "primary" {
  name = "example53.com"
}
