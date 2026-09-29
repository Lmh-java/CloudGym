# Pre-existing: the storefront's public hosted zone. Nothing records its DNS queries yet —
# the zone carries no query logging configuration, the account holds no CloudWatch Logs
# resource policy, and no log group exists under /aws/route53/.

resource "aws_route53_zone" "primary" {
  name    = "example53.com"
  comment = "storefront public zone"

  tags = {
    Name  = "example53.com"
    Owner = "dns-platform"
  }
}
