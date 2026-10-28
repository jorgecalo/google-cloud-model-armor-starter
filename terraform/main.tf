# ============================================================================
# [GitHub File 2/5]: terraform/main.tf
# Purpose: Declarative Model Armor Template (PIJB + SDP + Malicious URI + RAI)
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
}

variable "location" {
  description = "Google Cloud region for the Model Armor template"
  type        = string
  default     = "europe-west1"
}

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
}
