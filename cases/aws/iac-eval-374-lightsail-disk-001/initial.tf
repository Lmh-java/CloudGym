# Pre-existing: the billing service's ledger archive. `billing-ledger-archive` is the storage
# the service already keeps in this account — 16 GB of block storage in the account's first
# availability zone, carrying the service's attribution, attached to nothing. The host the
# service writes its extracts from, and the two extract disks that hang off it, are the task:
# at S0 the account holds no Lightsail instance at all, no extract disk and no attachment.

data "aws_availability_zones" "available" {
  state = "available"

  filter {
    name   = "opt-in-status"
    values = ["opt-in-not-required"]
  }
}

resource "aws_lightsail_disk" "archive" {
  name              = "billing-ledger-archive"
  size_in_gb        = 16
  availability_zone = data.aws_availability_zones.available.names[0]

  tags = {
    Service = "billing"
    Owner   = "billing-team"
  }
}
