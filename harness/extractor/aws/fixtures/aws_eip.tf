resource "aws_eip" "capability" {
  domain = "vpc"

  tags = {
    Name = "cloudgym-capability"
  }
}
