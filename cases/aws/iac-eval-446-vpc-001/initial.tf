# Pre-existing: the application's network, the one whose DHCP settings the task is about. The
# prompt refers to it as given — the Windows workload already runs in it — and asks only for
# the settings it should hand out. It is marked as the windomain workload so it can be told
# apart from the region's default network.
#
# Nothing of the task exists yet. At S0 the account holds no option set of its own: this
# network resolves through the account's default set (AmazonProvidedDNS, no NetBIOS server),
# which every account has and nobody stood up. No set in the region hands out the domain name
# or the resolvers the task asks for, no other network in the account is paired with this one,
# and nothing is recorded on it about what it must keep resolving through — so nothing here
# already satisfies the task or already carries a norm.

resource "aws_vpc" "default" {
  cidr_block = "192.168.0.0/16"

  tags = {
    Name     = "windomain-vpc"
    Workload = "windomain"
  }
}
