# UC9-EKS-Cluster

## If you're running Terraform ##

 **CodeBuild or ECS and have configured an IAM Task Role, _Terraform can use the container's Task Role_**. 

This support is based on the underlying AWS_CONTAINER_CREDENTIALS_RELATIVE_URI and AWS_CONTAINER_CREDENTIALS_FULL_URI environment variables being automatically set by those services or manually for advanced usage.

If you're running Terraform on EKS and have configured IAM Roles for Service Accounts (IRSA), Terraform can use the pod's role. 

This support is based on the underlying AWS_ROLE_ARN and AWS_WEB_IDENTITY_TOKEN_FILE environment variables being automatically set by Kubernetes or manually for advanced usage.
