# ============================================================================
# terraform/main.tf
# Purpose: Enable APIs, bind least-privilege IAM, and deploy Model Armor Template
# ============================================================================
terraform {
  required_version = ">= 1.5.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 6.12.0"
    }
  }
}

variable "project_id" {
  description = "Google Cloud Project ID where the Model Armor template is deployed"
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.project_id))
    error_message = "project_id must be a valid Google Cloud project ID."
  }
}

variable "location" {
  description = "Google Cloud region for the Model Armor template"
  type        = string
  default     = "europe-west1"

  validation {
    condition     = can(regex("^[a-z]+-[a-z]+[0-9]+$", var.location))
    error_message = "location must be a valid Google Cloud region (e.g., europe-west1, us-central1)."
  }
}

variable "app_service_account_email" {
  description = "Service Account email of the AI application that calls Model Armor"
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9-]+@[a-z0-9-]+\\.iam\\.gserviceaccount\\.com$", var.app_service_account_email))
    error_message = "app_service_account_email must be a valid Google Cloud service account email (prevents wildcard IAM bindings)."
  }
}

# Enable required Google Cloud APIs
resource "google_project_service" "model_armor_apis" {
  for_each = toset([
    "modelarmor.googleapis.com",
    "aiplatform.googleapis.com", # Gemini Enterprise Agent Platform (formerly Vertex AI)
    "logging.googleapis.com",
  ])
  project            = var.project_id
  service            = each.key
  disable_on_destroy = false
}

# Grant least-privilege runtime role to your AI application Service Account
resource "google_project_iam_member" "app_model_armor_user" {
  project    = var.project_id
  role       = "roles/modelarmor.user"
  member     = "serviceAccount:${var.app_service_account_email}"
  depends_on = [google_project_service.model_armor_apis]
}

# Declarative Model Armor Security Template
resource "google_model_armor_template" "agent_security_policy" {
  project     = var.project_id
  location    = var.location
  template_id = "agent-security-policy"

  filter_config {
    # 1. Block Prompt Injection & Jailbreaks at Low-and-Above confidence
    pi_and_jailbreak_filter_settings {
      filter_enforcement = "ENABLED"
      confidence_level   = "LOW_AND_ABOVE"
    }

    # 2. Enable Sensitive Data Protection (SDP / DLP)
    sdp_settings {
      basic_config {
        filter_enforcement = "ENABLED"
      }
    }

    # 3. Block Malicious URLs via Google Web Risk
    malicious_uri_filter_settings {
      filter_enforcement = "ENABLED"
    }

    # 4. Responsible AI (RAI) Safety Filters
    rai_settings {
      rai_filters {
        filter_type      = "HATE_SPEECH"
        confidence_level = "MEDIUM_AND_ABOVE"
      }
      rai_filters {
        filter_type      = "HARASSMENT"
        confidence_level = "MEDIUM_AND_ABOVE"
      }
      rai_filters {
        filter_type      = "DANGEROUS"
        confidence_level = "LOW_AND_ABOVE"
      }
      rai_filters {
        filter_type      = "SEXUALLY_EXPLICIT"
        confidence_level = "MEDIUM_AND_ABOVE"
      }
    }
  }

  # Enforce blocking mode, fail-closed partial invocation handling,
  # multilingual detection, and Cloud Logging audit trails for SanitizeOperation
  template_metadata {
    enforcement_type                   = "INSPECT_AND_BLOCK"
    ignore_partial_invocation_failures = false
    log_sanitize_operations            = true
    log_template_operations            = true

    multi_language_detection {
      enable_multi_language_detection = true
    }
  }

  depends_on = [google_project_service.model_armor_apis]
}
