data "aws_ami" "dependency" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-x86_64"]
  }
}

resource "aws_vpc" "dependency" {
  cidr_block = "10.243.0.0/16"
}

resource "aws_subnet" "dependency" {
  vpc_id     = aws_vpc.dependency.id
  cidr_block = "10.243.1.0/24"
}

resource "aws_lb_target_group" "dependency" {
  name_prefix = "cwcap-"
  port        = 80
  protocol    = "HTTP"
  vpc_id      = aws_vpc.dependency.id
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

  lifecycle {
    ignore_changes = [target_group_arns]
  }
}

resource "aws_autoscaling_attachment" "capability" {
  autoscaling_group_name = aws_autoscaling_group.dependency.name
  lb_target_group_arn    = aws_lb_target_group.dependency.arn
}
