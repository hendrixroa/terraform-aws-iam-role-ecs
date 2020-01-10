# IAM ROLE ECS

IAM Roles for AWS ECS prebuilt ready to use with integration of S3, Codedeploy, Service role, KMS key and more. 

- Terraform: `0.12.+`

## How to use

```hcl
module "awesome-iam-ecs-roles" {
  source = "hendrixroa/iam-role-ecs/aws"
}
```

Outputs list:

1. ecs_service: For ecs service
1. ecs_exec: for ecs service execution
1. ecs_task: for ecs task execution
1. ecs_autoscale_role: for ecs autoscaling
1. ecs_codedeploy: for codedeploy and blue green deployment
