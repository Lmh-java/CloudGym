data "aws_elastic_beanstalk_solution_stack" "dependency" {
  most_recent = true
  name_regex  = "^64bit Amazon Linux 2023 (.*) running Python 3.12$"
}

# t3.micro is not offered in every zone (us-east-1e lacks it), so pin the subnet to a zone
# that has it rather than letting EC2 pick.
data "aws_ec2_instance_type_offerings" "dependency" {
  location_type = "availability-zone"
  filter {
    name   = "instance-type"
    values = ["t3.micro"]
  }
}

resource "aws_vpc" "dependency" {
  cidr_block           = "10.239.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
}

resource "aws_internet_gateway" "dependency" {
  vpc_id = aws_vpc.dependency.id
}

resource "aws_subnet" "dependency" {
  vpc_id                  = aws_vpc.dependency.id
  cidr_block              = "10.239.1.0/24"
  availability_zone       = sort(data.aws_ec2_instance_type_offerings.dependency.locations)[0]
  map_public_ip_on_launch = true
}

resource "aws_route_table" "dependency" {
  vpc_id = aws_vpc.dependency.id
}

resource "aws_route" "dependency" {
  route_table_id         = aws_route_table.dependency.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.dependency.id
}

resource "aws_route_table_association" "dependency" {
  subnet_id      = aws_subnet.dependency.id
  route_table_id = aws_route_table.dependency.id
}

resource "aws_iam_role" "dependency" {
  name_prefix = "cloudgym-capability-"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "dependency" {
  role       = aws_iam_role.dependency.name
  policy_arn = "arn:aws:iam::aws:policy/AWSElasticBeanstalkWebTier"
}

resource "aws_iam_instance_profile" "dependency" {
  name_prefix = "cloudgym-capability-"
  role        = aws_iam_role.dependency.name
}

resource "aws_elastic_beanstalk_application" "dependency" {
  name        = "cloudgym-capability-env-app"
  description = "cloudgym extractor capability fixture"
}

# Single instance, no load balancer, basic health: the cheapest shape that still exercises
# the environment lifecycle. Auto Scaling launches the instance through its service-linked
# role, which the SCP's instance-type guardrail does not reach, so pin the type here.
resource "aws_elastic_beanstalk_environment" "capability" {
  name                = "cloudgym-capability-env"
  application         = aws_elastic_beanstalk_application.dependency.name
  solution_stack_name = data.aws_elastic_beanstalk_solution_stack.dependency.name
  tier                = "WebServer"

  setting {
    namespace = "aws:elasticbeanstalk:environment"
    name      = "EnvironmentType"
    value     = "SingleInstance"
  }
  setting {
    namespace = "aws:elasticbeanstalk:healthreporting:system"
    name      = "SystemType"
    value     = "basic"
  }
  setting {
    namespace = "aws:autoscaling:launchconfiguration"
    name      = "IamInstanceProfile"
    value     = aws_iam_instance_profile.dependency.name
  }
  setting {
    namespace = "aws:ec2:instances"
    name      = "InstanceTypes"
    value     = "t3.micro"
  }
  setting {
    namespace = "aws:ec2:vpc"
    name      = "VPCId"
    value     = aws_vpc.dependency.id
  }
  setting {
    namespace = "aws:ec2:vpc"
    name      = "Subnets"
    value     = aws_subnet.dependency.id
  }
  setting {
    namespace = "aws:ec2:vpc"
    name      = "AssociatePublicIpAddress"
    value     = "true"
  }

  depends_on = [aws_route.dependency, aws_route_table_association.dependency, aws_iam_role_policy_attachment.dependency]
}
