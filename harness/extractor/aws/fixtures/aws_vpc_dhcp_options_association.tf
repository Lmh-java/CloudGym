resource "aws_vpc" "dependency" {
  cidr_block = "10.244.0.0/16"
}

resource "aws_vpc_dhcp_options" "dependency" {
  domain_name         = "capability.cloudgym.internal"
  domain_name_servers = ["AmazonProvidedDNS"]
}

resource "aws_vpc_dhcp_options_association" "capability" {
  vpc_id          = aws_vpc.dependency.id
  dhcp_options_id = aws_vpc_dhcp_options.dependency.id
}
