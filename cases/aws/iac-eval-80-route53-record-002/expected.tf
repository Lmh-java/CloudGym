# IaC-Eval reference output for row 80 (provider/terraform blocks dropped; the pre-existing
# VPC copied verbatim from initial.tf). The clean witness of the task with nobody else acting
# on the account: the application's own private zone for internal.example53.com attached to
# main-vpc, and the orders API endpoint published in it as a non-alias A record.

resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "main-vpc"
  }
}

resource "aws_route53_zone" "private_zone" {
  name = "internal.example53.com"

  vpc {
    vpc_id = aws_vpc.main.id
  }
}

resource "aws_route53_record" "internal_record" {
  zone_id = aws_route53_zone.private_zone.zone_id
  name    = "api.internal.example53.com"
  type    = "A"
  ttl     = "300"
  records = ["10.0.1.101"]
}
