# Pre-existing: the application VPC whose DHCP settings the task is about. It
# already holds the account's 192.168.0.0/16 address space and carries the
# workload's Name tag. Like every freshly created VPC it still uses the
# region's default DHCP options set: no custom domain name, no custom name
# servers and no NetBIOS name server are configured for it at S0, and no
# non-default DHCP options set exists in the account.

resource "aws_vpc" "default" {
  cidr_block = "192.168.0.0/16"

  tags = {
    Name = "windomain-vpc"
  }
}
