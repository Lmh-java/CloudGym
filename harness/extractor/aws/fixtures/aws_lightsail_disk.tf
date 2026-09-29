resource "aws_lightsail_disk" "capability" {
  # aws_lightsail_disk has no name_prefix; a leaked previous run fails the apply visibly.
  name              = "cloudgym-capability-disk"
  size_in_gb        = 8
  availability_zone = "us-east-1a"

  tags = {
    Name = "cloudgym-capability"
  }
}
