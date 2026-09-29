resource "aws_lightsail_instance" "capability" {
  # aws_lightsail_instance has no name_prefix; a leaked previous run fails the apply visibly.
  name              = "cloudgym-capability-ls"
  availability_zone = "us-east-1a"
  blueprint_id      = "amazon_linux_2023"
  bundle_id         = "nano_3_0"

  tags = {
    Name = "cloudgym-capability"
  }
}
