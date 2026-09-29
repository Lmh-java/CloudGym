resource "aws_vpc_dhcp_options" "capability" {
  domain_name         = "capability.cloudgym.internal"
  domain_name_servers = ["AmazonProvidedDNS"]
  ntp_servers         = ["169.254.169.123"]

  tags = {
    Name = "cloudgym-capability"
  }
}
