output "athena_workgroup" {
  value = aws_athena_workgroup.monitoring.name
}

output "athena_database" {
  value = aws_glue_catalog_database.monitoring.name
}

# Convenience: the LOG_SOURCES JSON the binary expects (name -> sanitized table).
output "log_sources_env" {
  value = jsonencode([for name, _ in var.log_sources : { name = name, table = replace(name, "-", "_") }])
}
