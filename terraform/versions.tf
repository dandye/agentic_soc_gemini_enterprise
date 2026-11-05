terraform {
  required_version = ">= 1.9.0"

  required_providers {
    # google-beta ONLY. Every Agent Gateway, Agent Registry, Agent Identity,
    # and Reasoning Engine resource in this stack is beta-only. Every google_*
    # resource and data block explicitly sets `provider = google-beta`.
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "~> 8.7"
    }
    time = {
      source  = "hashicorp/time"
      version = "~> 0.13"
    }
  }
}
