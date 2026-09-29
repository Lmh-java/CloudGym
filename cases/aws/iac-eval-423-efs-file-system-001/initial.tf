# Pre-existing: the product's shared file system. `my-product` is up and empty, on the
# bursting throughput the account hands out by default, and it carries the service's
# attribution. Nothing has been done to it beyond creating it: it has no file system policy
# at S0 (so the account-wide default applies and any principal that can reach it may mount,
# read and write it, over TLS or not), and it has no mount target in any VPC, so nothing in
# the account can actually reach it. The policy and the mount target are the task's diff.

resource "aws_efs_file_system" "fs" {
  creation_token  = "my-product"
  throughput_mode = "bursting"

  tags = {
    Name    = "my-product"
    Service = "my-product"
    Owner   = "product-team"
  }
}
