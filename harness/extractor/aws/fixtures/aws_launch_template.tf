data "aws_ami" "dependency" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-x86_64"]
  }
}

resource "aws_launch_template" "capability" {
  name_prefix   = "cloudgym-capability-"
  image_id      = data.aws_ami.dependency.id
  instance_type = "t3.micro"

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name = "cloudgym-capability"
    }
  }
}
