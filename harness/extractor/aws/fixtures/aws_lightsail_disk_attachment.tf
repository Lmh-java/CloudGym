resource "aws_lightsail_instance" "dependency" {
  name              = "cloudgym-capability-ls-attach"
  availability_zone = "us-east-1a"
  blueprint_id      = "amazon_linux_2023"
  bundle_id         = "nano_3_0"
}

resource "aws_lightsail_disk" "dependency" {
  name              = "cloudgym-capability-disk-attach"
  size_in_gb        = 8
  availability_zone = "us-east-1a"
}

resource "aws_lightsail_disk_attachment" "capability" {
  disk_name     = aws_lightsail_disk.dependency.name
  instance_name = aws_lightsail_instance.dependency.name
  disk_path     = "/dev/xvdf"
}
