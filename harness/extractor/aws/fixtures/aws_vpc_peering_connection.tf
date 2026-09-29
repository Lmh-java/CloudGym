resource "aws_vpc" "dependency" {
  cidr_block = "10.246.0.0/24"
}

resource "aws_vpc" "peer" {
  cidr_block = "10.247.0.0/24"
}

resource "aws_vpc_peering_connection" "capability" {
  vpc_id      = aws_vpc.dependency.id
  peer_vpc_id = aws_vpc.peer.id
  auto_accept = true

  tags = {
    Name = "cloudgym-capability"
  }
}
