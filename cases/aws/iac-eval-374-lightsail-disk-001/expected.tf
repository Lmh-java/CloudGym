# IaC-Eval reference output for row 374 (provider/terraform blocks dropped; the service's
# pre-existing ledger archive carried over verbatim from initial.tf, which is what fixes the
# availability zone everything else lands in, and the blueprint and bundle the sandbox runs
# Lightsail on). The clean witness of the task with nobody else acting: the host `billing-worker`
# stands beside the archive, and the two 8 GB extract disks carrying the service's attribution
# hang off it, `billing-extracts-1` at /dev/xvdf and `billing-extracts-2` at /dev/xvdg.

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

resource "aws_lightsail_instance" "worker" {
  name              = "billing-worker"
  availability_zone = aws_lightsail_disk.archive.availability_zone
  blueprint_id      = "amazon_linux_2023"
  bundle_id         = "nano_3_0"
}

resource "aws_lightsail_disk" "extracts_1" {
  name              = "billing-extracts-1"
  size_in_gb        = 8
  availability_zone = aws_lightsail_disk.archive.availability_zone

  tags = {
    Service = "billing"
    Owner   = "billing-team"
  }
}

resource "aws_lightsail_disk" "extracts_2" {
  name              = "billing-extracts-2"
  size_in_gb        = 8
  availability_zone = aws_lightsail_disk.archive.availability_zone

  tags = {
    Service = "billing"
    Owner   = "billing-team"
  }
}

resource "aws_lightsail_disk_attachment" "extracts_1" {
  disk_name     = aws_lightsail_disk.extracts_1.name
  instance_name = aws_lightsail_instance.worker.name
  disk_path     = "/dev/xvdf"
}

resource "aws_lightsail_disk_attachment" "extracts_2" {
  disk_name     = aws_lightsail_disk.extracts_2.name
  instance_name = aws_lightsail_instance.worker.name
  disk_path     = "/dev/xvdg"
}
