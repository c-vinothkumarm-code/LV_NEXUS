# DRAFT - not applied and not validated against a live project. Review before any `terraform apply`.
# Nothing here is deployed without explicit approval. All identities are read-only towards the clouds.

variable "project_id" { type = string }
variable "region" {
  type    = string
  default = "asia-south1"
}
variable "image"      { type = string }                # Artifact Registry image built from ./Dockerfile
variable "db_url_secret"     { type = string }         # Secret Manager secret IDs (values are created out of band)
variable "session_secret"    { type = string }
variable "env" {
  type        = map(string)
  description = "Non-secret settings: GCP_ORGANIZATION_ID, AWS_MEMBER_ROLE_NAME, AZURE_TENANT_ID, ..."
  default     = {}
}

provider "google" {
  project = var.project_id
  region  = var.region
}

resource "google_service_account" "control_plane" {
  account_id   = "mcp-control-plane"
  display_name = "Multi-Cloud Control Plane (read-only collector)"
}

resource "google_service_account" "scheduler" {
  account_id   = "mcp-scheduler"
  display_name = "Invokes control-plane jobs"
}

locals {
  secret_env = { DATABASE_URL = var.db_url_secret, SECRET_KEY = var.session_secret }
  plain_env  = merge({ APP_ENV = "production", AUTH_MODE = "google" }, var.env)
  jobs = {                               # job name => cron (Asia/Kolkata)
    account_discovery = "*/15 * * * *"
  }
}

resource "google_secret_manager_secret_iam_member" "access" {
  for_each  = local.secret_env
  secret_id = each.value
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.control_plane.email}"
}

resource "google_cloud_run_v2_service" "api" {
  name     = "mcp-api"
  location = var.region
  ingress  = "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"
  template {
    service_account = google_service_account.control_plane.email
    containers {
      image = var.image
      dynamic "env" {
        for_each = local.plain_env
        content {
          name  = env.key
          value = env.value
        }
      }
      dynamic "env" {
        for_each = local.secret_env
        content {
          name = env.key
          value_source {
            secret_key_ref {
              secret  = env.value
              version = "latest"
            }
          }
        }
      }
    }
  }
}

resource "google_cloud_run_v2_job" "job" {
  for_each = local.jobs
  name     = "mcp-${replace(each.key, "_", "-")}"
  location = var.region
  template {
    template {
      service_account = google_service_account.control_plane.email
      max_retries     = 2
      timeout         = "840s"
      containers {
        image   = var.image
        command = ["python", "-m", "app.workers.run", each.key]
        dynamic "env" {
          for_each = local.plain_env
          content {
            name  = env.key
            value = env.value
          }
        }
        dynamic "env" {
          for_each = local.secret_env
          content {
            name = env.key
            value_source {
              secret_key_ref {
                secret  = env.value
                version = "latest"
              }
            }
          }
        }
      }
    }
  }
}

resource "google_cloud_run_v2_job_iam_member" "invoker" {
  for_each = local.jobs
  name     = google_cloud_run_v2_job.job[each.key].name
  location = var.region
  role     = "roles/run.invoker"
  member   = "serviceAccount:${google_service_account.scheduler.email}"
}

resource "google_cloud_scheduler_job" "trigger" {
  for_each  = local.jobs
  name      = "mcp-${replace(each.key, "_", "-")}"
  schedule  = each.value
  time_zone = "Asia/Kolkata"
  http_target {
    http_method = "POST"
    uri         = "https://run.googleapis.com/v2/projects/${var.project_id}/locations/${var.region}/jobs/${google_cloud_run_v2_job.job[each.key].name}:run"
    oauth_token { service_account_email = google_service_account.scheduler.email }
  }
}

# Event-driven discovery: an organisation log sink can publish project-creation audit entries here;
# a push subscription then calls POST /api/v1/events/pubsub (see docs/deployment).
resource "google_pubsub_topic" "scope_events" { name = "mcp-scope-events" }
resource "google_pubsub_topic" "dead_letter"  { name = "mcp-scope-events-dlq" }
