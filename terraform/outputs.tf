output "reports_bucket_name" {
  description = "S3 bucket for security reports."
  value       = aws_s3_bucket.reports.id
}

output "reports_bucket_arn" {
  description = "ARN of the S3 reports bucket."
  value       = aws_s3_bucket.reports.arn
}

output "github_actions_role_arn" {
  description = "IAM role ARN for GitHub Actions OIDC."
  value       = aws_iam_role.github_actions.arn
}
