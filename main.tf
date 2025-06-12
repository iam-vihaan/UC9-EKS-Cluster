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
  ecs_cluster_name = module.ecs.cluster_name
}
