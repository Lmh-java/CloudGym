# Pre-existing: the orders service's archive disk. `orders-archive` is the storage the service
# already keeps in this account — 8 GB of block storage in the account's first availability
# zone, carrying the service's attribution, attached to nothing. The host the service runs on
# and the uploads disk that hangs off it are the task: at S0 the account holds no Lightsail
# instance at all, and no attachment.

data "aws_availability_zones" "available" {
  state = "available"

  filter {
    name   = "opt-in-status"
    values = ["opt-in-not-required"]
  }
}

resource "aws_lightsail_disk" "archive" {
  name              = "orders-archive"
  size_in_gb        = 8
  availability_zone = data.aws_availability_zones.available.names[0]

  tags = {
    Service = "orders"
    Owner   = "orders-team"
  }
}
