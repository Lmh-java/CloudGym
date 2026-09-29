# IaC-Eval reference output for row 372 (provider/terraform blocks dropped; the service's
# pre-existing archive disk carried over from initial.tf, which is what fixes the zone
# everything else lands in, and the blueprint and bundle the sandbox runs Lightsail on). The
# clean witness of the task with nobody else acting: the host `orders-web` stands beside the
# archive, and the 8 GB disk `orders-web-data` carrying the service's attribution is attached
# to it at /dev/xvdf.

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

resource "aws_lightsail_disk" "data" {
  name              = "orders-web-data"
  size_in_gb        = 8
  availability_zone = aws_lightsail_disk.archive.availability_zone

  tags = {
    Service = "orders"
    Owner   = "orders-team"
  }
}

resource "aws_lightsail_instance" "web" {
  name              = "orders-web"
  availability_zone = aws_lightsail_disk.archive.availability_zone
  blueprint_id      = "amazon_linux_2023"
  bundle_id         = "nano_3_0"
}

resource "aws_lightsail_disk_attachment" "data" {
  disk_name     = aws_lightsail_disk.data.name
  instance_name = aws_lightsail_instance.web.name
  disk_path     = "/dev/xvdf"
}
