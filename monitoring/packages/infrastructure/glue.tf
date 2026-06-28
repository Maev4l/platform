resource "aws_glue_catalog_database" "monitoring" {
  name = "platform-monitoring"
}

resource "aws_glue_catalog_table" "source" {
  for_each      = var.log_sources
  name          = replace(each.key, "-", "_")
  database_name = aws_glue_catalog_database.monitoring.name
  table_type    = "EXTERNAL_TABLE"

  parameters = {
    classification              = "parquet"
    "projection.enabled"        = "true"
    "projection.year.type"      = "integer"
    "projection.year.range"     = "2024,2030"
    "projection.year.digits"    = "4"
    "projection.month.type"     = "integer"
    "projection.month.range"    = "1,12"
    "projection.month.digits"   = "2"
    "projection.day.type"       = "integer"
    "projection.day.range"      = "1,31"
    "projection.day.digits"     = "2"
    "storage.location.template" = "s3://${each.value.bucket}/${each.value.prefix}/year=$${year}/month=$${month}/day=$${day}"
  }

  storage_descriptor {
    location      = "s3://${each.value.bucket}/${each.value.prefix}/"
    input_format  = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat"

    ser_de_info {
      serialization_library = "org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe"
    }

    columns {
      name = "date"
      type = "string"
    }
    columns {
      name = "time"
      type = "string"
    }
    columns {
      name = "c_ip"
      type = "string"
    }
    columns {
      name = "c_country"
      type = "string"
    }
    columns {
      name = "asn"
      type = "string"
    }
    columns {
      name = "cs_method"
      type = "string"
    }
    columns {
      name = "cs_protocol"
      type = "string"
    }
    columns {
      name = "cs_host"
      type = "string"
    }
    columns {
      name = "cs_uri_stem"
      type = "string"
    }
    columns {
      name = "cs_uri_query"
      type = "string"
    }
    columns {
      name = "sc_status"
      type = "string"
    }
    columns {
      name = "x_edge_result_type"
      type = "string"
    }
    columns {
      name = "x_edge_location"
      type = "string"
    }
    columns {
      name = "cs_user_agent"
      type = "string"
    }
  }

  partition_keys {
    name = "year"
    type = "string"
  }
  partition_keys {
    name = "month"
    type = "string"
  }
  partition_keys {
    name = "day"
    type = "string"
  }
}
