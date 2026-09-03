resource "aws_s3_bucket_public_access_block" "agent_logs" {
  bucket            = "project-sonic-agent-logs"
  block_public_acls = true
}
