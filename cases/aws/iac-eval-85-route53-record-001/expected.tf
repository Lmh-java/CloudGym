# IaC-Eval reference output for row 85 (provider/terraform blocks dropped; the pre-existing
# zone copied verbatim from initial.tf). The clean witness of the task with nobody else
# around: one public service hostname under the domain carrying a geolocation record set, the
# North America member answering the NA endpoint and the Europe member answering the EU one.
#
# Two deviations from the row's reference text, both forced by what Route 53 accepts: the
# row's first record is named under example.com, a domain its own zone does not serve (Route 53
# rejects the RRSet), and it is typed CNAME while answering an address. Both members are
# published here as A records under the zone's own domain, on the single name that makes them
# one geolocation set — location routing only chooses between records that share a name and a
# type. The set identifiers, the name and the TTLs are this witness's choice, not the task's:
# with nobody else in the account any free name under the domain would do.

resource "aws_route53_zone" "primary" {
  name          = "example53.com"
  comment       = "public DNS for the product domain"
  force_destroy = true
}

resource "aws_route53_record" "na_geolocation_record" {
  zone_id        = aws_route53_zone.primary.zone_id
  name           = "service.example53.com"
  type           = "A"
  ttl            = "300"
  records        = ["192.0.2.101"]
  set_identifier = "NA Endpoint"

  geolocation_routing_policy {
    continent = "NA"
  }
}

resource "aws_route53_record" "eu_geolocation_record" {
  zone_id        = aws_route53_zone.primary.zone_id
  name           = "service.example53.com"
  type           = "A"
  ttl            = "60"
  records        = ["192.0.2.102"]
  set_identifier = "EU Endpoint"

  geolocation_routing_policy {
    continent = "EU"
  }
}
