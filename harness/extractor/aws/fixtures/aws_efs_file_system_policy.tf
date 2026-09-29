resource "aws_efs_file_system" "dependency" {
  creation_token = "cloudgym-capability-efs-policy"
}

resource "aws_efs_file_system_policy" "capability" {
  file_system_id = aws_efs_file_system.dependency.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = { AWS = "*" }
      Action    = "*"
      Resource  = aws_efs_file_system.dependency.arn
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}
