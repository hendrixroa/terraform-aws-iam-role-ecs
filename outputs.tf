output "ecs_service" {
  value = aws_iam_role_policy.ecs_service.id
}

output "ecs_exec" {
  value = aws_iam_role.ecs_exec.arn
}

output "ecs_task" {
  value = aws_iam_role.ecs_task.arn
}

output "ecs_autoscale_role" {
  value = aws_iam_role.ecs_autoscale_role.arn
}

output "ecs_codedeploy" {
  value = aws_iam_role.ecs_codedeploy.arn
}
