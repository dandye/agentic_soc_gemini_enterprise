# Data Access audit logging for `iap.googleapis.com` (`ADMIN_READ` + `DATA_READ`)
# so per-tool allow and deny verdicts record the calling SPIFFE `principalSubject`
# and `mcp_tool_name` in `cloudaudit.googleapis.com/data_access`.

resource "google_project_iam_audit_config" "iap" {
  count = var.enable_iap_data_access_logs ? 1 : 0

  provider = google-beta
  project  = var.project_id
  service  = "iap.googleapis.com"

  audit_log_config {
    log_type = "ADMIN_READ"
  }

  audit_log_config {
    log_type = "DATA_READ"
  }
}

resource "google_project_iam_audit_config" "modelarmor" {
  count = var.enable_modelarmor_data_access_logs ? 1 : 0

  provider = google-beta
  project  = var.project_id
  service  = "modelarmor.googleapis.com"

  audit_log_config {
    log_type = "ADMIN_READ"
  }

  audit_log_config {
    log_type = "DATA_READ"
  }

  audit_log_config {
    log_type = "DATA_WRITE"
  }
}
