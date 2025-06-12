terraform {
  backend "s3" {
    bucket       = "kasi-hcl-bucket-uc8"
    key          = "kasi-hcl-bucket-uc8/statefile.tfstate"
    region       = "us-east-1"
    encrypt      = true
    use_lockfile = true
  }
}
