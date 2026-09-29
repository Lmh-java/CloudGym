data "aws_ami" "dependency" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-x86_64"]
  }
}

resource "aws_vpc" "dependency" {
  cidr_block = "10.241.0.0/16"
}

resource "aws_subnet" "dependency" {
  vpc_id     = aws_vpc.dependency.id
  cidr_block = "10.241.1.0/24"
}

resource "aws_launch_template" "dependency" {
  name_prefix   = "cloudgym-capability-"
  image_id      = data.aws_ami.dependency.id
  instance_type = "t3.micro"
}

# Zero desired capacity: the group exists with its full document but launches nothing,
# so the smoke costs nothing and settles at once.
resource "aws_autoscaling_group" "capability" {
  name_prefix      = "cloudgym-capability-"
  min_size         = 0
  max_size         = 1
  desired_capacity = 0
  launch_template {
    id      = aws_launch_template.dependency.id
    version = "$Latest"
  }
  vpc_zone_identifier = [aws_subnet.dependency.id]
  health_check_type   = "EC2"

  tag {
    key                 = "cloudgym"
    value               = "capability"
    propagate_at_launch = false
  }
}
