data "aws_ami" "dependency" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-x86_64"]
  }
}

resource "aws_vpc" "dependency" {
  cidr_block = "10.242.0.0/16"
}

resource "aws_subnet" "dependency" {
  vpc_id     = aws_vpc.dependency.id
  cidr_block = "10.242.1.0/24"
}

resource "aws_launch_template" "dependency" {
  name_prefix   = "cloudgym-capability-"
  image_id      = data.aws_ami.dependency.id
  instance_type = "t3.micro"
}

resource "aws_autoscaling_group" "dependency" {
  name_prefix      = "cloudgym-capability-"
  min_size         = 0
  max_size         = 1
  desired_capacity = 0
  launch_template {
    id      = aws_launch_template.dependency.id
    version = "$Latest"
  }
  vpc_zone_identifier = [aws_subnet.dependency.id]
}

# Policy names are scoped to their group, so a fixed name cannot collide across runs.
resource "aws_autoscaling_policy" "capability" {
  name                   = "cloudgym-capability-scale-down"
  autoscaling_group_name = aws_autoscaling_group.dependency.name
  policy_type            = "SimpleScaling"
  adjustment_type        = "ChangeInCapacity"
  scaling_adjustment     = -1
  cooldown               = 120
}
