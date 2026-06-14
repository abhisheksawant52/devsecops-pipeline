variable "region" {
  description = "AWS region."
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Project name used for resource naming."
  type        = string
  default     = "devsecops-pipeline"
}

variable "github_org" {
  description = "GitHub organization or username for OIDC trust."
  type        = string
  default     = "abhisheksawant52"
}

variable "github_repo" {
  description = "GitHub repository name for OIDC trust."
  type        = string
  default     = "devsecops-pipeline"
}

variable "tags" {
  description = "Tags to apply to all resources."
  type        = map(string)
  default = {
    project    = "devsecops-pipeline"
    managed_by = "terraform"
  }
}
