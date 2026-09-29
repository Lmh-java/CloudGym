resource "aws_route53_zone" "dependency" {
  name    = "cloudgym-capability-record.test"
  comment = "cloudgym extractor capability fixture"
}

resource "aws_route53_record" "capability" {
  zone_id = aws_route53_zone.dependency.zone_id
  name    = "www"
  type    = "A"
  ttl     = 300
  records = ["192.0.2.1"]
}
