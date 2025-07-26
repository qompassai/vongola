# vongola.hcl
# Qompass AI Vongola Config
# Copyright (C) 2025 Qompass AI, All rights reserved
# ----------------------------------------
service_name = "vongola"
worker_threads = 4

docker {
  enabled = false
  endpoint = "unix:///var/run/docker.sock"
  interval_secs = 15
  mode = "container"
}

lets_encrypt {
  enabled = true
  email = "your-email@example.com"
  staging = true
}

logging {
  enabled = true
  level = "INFO"
  access_logs_enabled = true
  error_logs_enabled = false
  format = "pretty"
  path = "/tmp"
  rotation = "daily"
}
paths {
  lets_encrypt = "/etc/vongola/letsencrypt"
}
routes = [
  {
    host      = "example.com"
    upstreams = [
      {
        ip      = "google.com"
        port    = 443
        sni     = "google.com"
        headers = { add = { name = "Host", value = "google.com" } }
      },
      {
        ip      = "10.1.2.23/24"
        network = "shared"
        port    = 3000
      }
    ]
    headers = {
      add    = [
        { name = "X-Forwarded-For", value = "<value>" },
        { name = "X-Api-Version", value = "<value>" }
      ]
      remove = [ { name = "Server" } ]
    }
    ssl = {
      path = {
        key = "/etc/vongola/certs/my-host.key"
        pem = "/etc/vongola/certs/my-host.pem"
      }
      self_signed_fallback = true
    }
    match_with = {
      path = { patterns = ["/api/*", "/*"] }
    }
    plugins = [
      { name    = "request_id" },
      { name    = "basic_auth", config = { user = "<user>", pass = "<pass>" } },
      { name    = "oauth2",     config = {
        provider   = "github",
        client_id  = "<client_id>",
        client_secret = "<client_secret>",
        jwt_secret = "<jwt_secret>",
        validations = [ { key = "team_id", value = ["<team_id>"] } ]
      } }
    ]
  }
]
