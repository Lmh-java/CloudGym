# Pre-existing: the account's public DNS for the product domain — the hosted zone
# example53.com. Nothing is published under it yet beyond the apex NS and SOA pair Route 53
# mints with every zone: at S0 no name under the domain answers an address, no record anywhere
# in the account carries a routing policy of any kind, and the account holds exactly one zone
# for this domain. The location-routed answers are the task.

resource "aws_route53_zone" "primary" {
  name          = "example53.com"
  comment       = "public DNS for the product domain"
  force_destroy = true
}
