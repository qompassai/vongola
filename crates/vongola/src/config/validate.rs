// /qompassai/vongola/crates/vongola/src/config/validate.rs
// Qompass AI Vongola Config Validation
// Copyright (C) 2025 Qompass AI, All rights reserved
/////////////////////////////////////////////////////
use anyhow::anyhow;
use super::Config;
/// given a Config struct, validate the values to ensure
/// That we program won't panic when we try to use them
pub fn check_config(config: &Config) -> Result<(), anyhow::Error> {
    if config.worker_threads.is_some_and(|v| v == 0) {
        return Err(anyhow!("Worker threads must be greater than 0"));
    }
    if config.docker.interval_secs.unwrap() == 0 {
        return Err(anyhow!("docker.interval_secs must be greater than 0"));
    }
    if config.lets_encrypt.email.contains("@example") || config.lets_encrypt.email.is_empty() {
        return Err(anyhow!(
            "lets_encrypt.email cannot be empty or an email from @example.com (the default value)"
        ));
    }
    if config.paths.lets_encrypt.as_os_str() == "" {
        return Err(anyhow!("paths.lets_encrypt cannot be empty"));
    }
    for (route_index, route) in config.routes.iter().enumerate() {
        for (upstream_index, upstream) in route.upstreams.iter().enumerate() {
            if upstream.ip.is_empty() {
                return Err(anyhow!(
                    "routes{}.upstreams{}.id cannot be empty",
                    route_index,
                    upstream_index
                ));
            }
            if upstream.port == 0 {
                return Err(anyhow!(
                    "routes{}.upstreams{}.port must be greater than 0",
                    route_index,
                    upstream_index
                ));
            }
        }
    }
    Ok(())
}
