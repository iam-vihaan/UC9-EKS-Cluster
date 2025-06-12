module "VPC" {
  source = "./modules/VPC"
  
  project_name       = var.project_name
  environment        = var.environment
  vpc_cidr          = var.vpc_cidr
  availability_zones = var.availability_zones
}

module "IAM" {
  source = "./modules/IAM"
  
  project_name = var.project_name
  environment  = var.environment
}

module "ECR" {
  source = "./modules/ECR"
  
  project_name = var.project_name
  environment  = var.environment
}

module "EKS" {
  source = "./modules/EKS"
  cluster_name  =  "my-cluster"
  cluster_version  =  "1.27"
  subnet_ids  =  "var.subnet_ids"
  vpc_id  =  var.vpc_id
  node_group_role_arn  =  var.node_group_role_arn
  cluster_service_role_arn  =  var.cluster_service_role_arn
  project_name             = var.project_name
  environment              = var.environment
  vpc_id                   = module.vpc.vpc_id
  private_subnet_ids       = module.vpc.private_subnet_ids
  public_subnet_ids        = module.vpc.public_subnet_ids
  cluster_name             = var.cluster_name
  cluster_version          = var.cluster_version
  node_groups              = var.node_groups
  
}

module "cloudwatch" {
  source = "./modules/cloudwatch"
  
  project_name    = var.project_name
  environment     = var.environment
  eks_cluster_name = module.EKS_cluster_name
}
