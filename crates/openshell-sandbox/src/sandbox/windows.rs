// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Windows sandbox implementation using MXC (Microsoft eXecution Containers).
//!
//! On Windows, process-level sandboxing is provided by MXC's AppContainer
//! backend via the `wxc-exec.exe` binary. This module translates OpenShell's
//! [`SandboxPolicy`] into an MXC JSON configuration and wraps process
//! execution through `wxc-exec.exe --config-base64`.
//!
//! # Binary discovery
//!
//! The `wxc-exec.exe` path is resolved in order:
//! 1. `OPENSHELL_WXC_EXEC_PATH` environment variable
//! 2. `wxc-exec.exe` on `PATH`
//! 3. Well-known build output locations relative to an `MXC_REPO_PATH` env var
//!
//! If the binary is not found, the sandbox falls back to unsandboxed execution
//! with an OCSF warning event.

use crate::policy::{NetworkMode, SandboxPolicy};
use base64::Engine;
use serde_json::json;
use std::path::PathBuf;
use tracing::{debug, warn};

/// MXC config schema version used for generated configurations.
const MXC_CONFIG_VERSION: &str = "0.4.0-alpha";

/// Environment variable to override the wxc-exec.exe path.
const WXC_EXEC_PATH_ENV: &str = "OPENSHELL_WXC_EXEC_PATH";

/// Environment variable pointing to the MXC repository root.
const MXC_REPO_PATH_ENV: &str = "MXC_REPO_PATH";

/// Translate an OpenShell [`SandboxPolicy`] into an MXC JSON config value.
///
/// The returned JSON matches the MXC 0.4.0-alpha config schema and can be
/// serialized and passed to `wxc-exec.exe --config-base64`.
pub fn translate_policy(
    program: &str,
    args: &[String],
    policy: &SandboxPolicy,
    workdir: Option<&str>,
) -> serde_json::Value {
    // Build the full command line (wxc-exec expects a single string).
    let command_line = if args.is_empty() {
        program.to_string()
    } else {
        format!("{program} {}", shell_join(args))
    };

    // Filesystem policy: map OpenShell read_only/read_write to MXC paths.
    let readonly_paths: Vec<String> = policy
        .filesystem
        .read_only
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();

    let mut readwrite_paths: Vec<String> = policy
        .filesystem
        .read_write
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();

    // If include_workdir is set and workdir is provided, add it to read-write.
    if policy.filesystem.include_workdir {
        if let Some(dir) = workdir {
            let dir_str = dir.to_string();
            if !readwrite_paths.contains(&dir_str) {
                readwrite_paths.push(dir_str);
            }
        }
    }

    // Network policy: map OpenShell NetworkMode to MXC network config.
    let network = match &policy.network.mode {
        NetworkMode::Block => json!({
            "defaultPolicy": "block"
        }),
        NetworkMode::Allow => json!({
            "defaultPolicy": "allow"
        }),
        NetworkMode::Proxy => {
            let mut net = json!({
                "defaultPolicy": "block"
            });
            if let Some(proxy) = &policy.network.proxy {
                if let Some(addr) = proxy.http_addr {
                    net["proxy"] = json!({ "localhost": addr.port() });
                }
            }
            net
        }
    };

    // AppContainer capabilities: grant network access based on policy.
    let capabilities = match &policy.network.mode {
        NetworkMode::Allow => json!(["internetClient", "privateNetworkClientServer"]),
        NetworkMode::Proxy => json!(["internetClient"]),
        NetworkMode::Block => json!([]),
    };

    json!({
        "version": MXC_CONFIG_VERSION,
        "containment": "appcontainer",
        "process": {
            "commandLine": command_line,
        },
        "lifecycle": {
            "destroyOnExit": true,
        },
        "appContainer": {
            "capabilities": capabilities,
        },
        "filesystem": {
            "readwritePaths": readwrite_paths,
            "readonlyPaths": readonly_paths,
        },
        "network": network,
    })
}

/// Discover the `wxc-exec.exe` binary path.
///
/// Returns `Some(path)` if a valid binary is found, `None` otherwise.
pub fn find_wxc_exec() -> Option<PathBuf> {
    // 1. Explicit environment variable.
    if let Ok(path) = std::env::var(WXC_EXEC_PATH_ENV) {
        let p = PathBuf::from(&path);
        if p.is_file() {
            debug!(%path, "Found wxc-exec via {WXC_EXEC_PATH_ENV}");
            return Some(p);
        }
        warn!(
            %path,
            "OPENSHELL_WXC_EXEC_PATH is set but file not found"
        );
    }

    // 2. Check PATH via `where.exe`.
    if let Ok(output) = std::process::Command::new("where.exe")
        .arg("wxc-exec.exe")
        .output()
    {
        if output.status.success() {
            if let Some(line) = String::from_utf8_lossy(&output.stdout).lines().next() {
                let p = PathBuf::from(line.trim());
                if p.is_file() {
                    debug!(path = %p.display(), "Found wxc-exec on PATH");
                    return Some(p);
                }
            }
        }
    }

    // 3. Well-known MXC repo build paths.
    if let Ok(repo) = std::env::var(MXC_REPO_PATH_ENV) {
        let candidates = [
            format!("{repo}\\src\\target\\release\\wxc-exec.exe"),
            format!("{repo}\\src\\target\\x86_64-pc-windows-msvc\\release\\wxc-exec.exe"),
            format!("{repo}\\src\\target\\aarch64-pc-windows-msvc\\release\\wxc-exec.exe"),
            format!("{repo}\\src\\target\\debug\\wxc-exec.exe"),
        ];
        for candidate in &candidates {
            let p = PathBuf::from(candidate);
            if p.is_file() {
                debug!(path = %p.display(), "Found wxc-exec in MXC repo build output");
                return Some(p);
            }
        }
    }

    None
}

/// Build the base64-encoded config argument for wxc-exec.
pub fn encode_config(config: &serde_json::Value) -> String {
    let json_bytes = serde_json::to_vec(config).expect("MXC config is always serializable");
    base64::engine::general_purpose::STANDARD.encode(&json_bytes)
}

/// Join arguments into a shell-safe command line string.
fn shell_join(args: &[String]) -> String {
    args.iter()
        .map(|a| {
            if a.contains(' ') || a.contains('"') {
                format!("\"{}\"", a.replace('"', "\\\""))
            } else {
                a.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{
        FilesystemPolicy, LandlockCompatibility, LandlockPolicy, NetworkMode, NetworkPolicy,
        ProcessPolicy, ProxyPolicy, SandboxPolicy,
    };
    use std::net::SocketAddr;

    fn test_policy(mode: NetworkMode) -> SandboxPolicy {
        SandboxPolicy {
            version: 1,
            filesystem: FilesystemPolicy {
                read_only: vec![PathBuf::from("/usr/bin"), PathBuf::from("C:\\tools")],
                read_write: vec![PathBuf::from("/workspace")],
                include_workdir: true,
            },
            network: NetworkPolicy {
                mode,
                proxy: Some(ProxyPolicy {
                    http_addr: Some("127.0.0.1:3128".parse::<SocketAddr>().unwrap()),
                }),
            },
            landlock: LandlockPolicy {
                compatibility: LandlockCompatibility::BestEffort,
            },
            process: ProcessPolicy {
                run_as_user: None,
                run_as_group: None,
            },
        }
    }

    #[test]
    fn translate_block_policy() {
        let policy = test_policy(NetworkMode::Block);
        let config = translate_policy("python", &["script.py".into()], &policy, Some("/workspace"));

        assert_eq!(config["version"], MXC_CONFIG_VERSION);
        assert_eq!(config["containment"], "appcontainer");
        assert_eq!(config["process"]["commandLine"], "python script.py");
        assert_eq!(config["network"]["defaultPolicy"], "block");
        assert_eq!(config["appContainer"]["capabilities"], json!([]));

        let rw = config["filesystem"]["readwritePaths"].as_array().unwrap();
        assert!(rw.iter().any(|v| v == "/workspace"));
    }

    #[test]
    fn translate_proxy_policy() {
        let policy = test_policy(NetworkMode::Proxy);
        let config = translate_policy("bash", &[], &policy, None);

        assert_eq!(config["network"]["defaultPolicy"], "block");
        assert_eq!(config["network"]["proxy"]["localhost"], 3128);
        assert_eq!(
            config["appContainer"]["capabilities"],
            json!(["internetClient"])
        );
    }

    #[test]
    fn translate_allow_policy() {
        let policy = test_policy(NetworkMode::Allow);
        let config = translate_policy("node", &["app.js".into()], &policy, None);

        assert_eq!(config["network"]["defaultPolicy"], "allow");
        assert_eq!(
            config["appContainer"]["capabilities"],
            json!(["internetClient", "privateNetworkClientServer"])
        );
    }

    #[test]
    fn workdir_added_when_include_workdir() {
        let policy = test_policy(NetworkMode::Block);
        let config = translate_policy("python", &[], &policy, Some("C:\\Users\\agent\\workspace"));

        let rw = config["filesystem"]["readwritePaths"].as_array().unwrap();
        assert!(rw.iter().any(|v| v == "C:\\Users\\agent\\workspace"));
    }

    #[test]
    fn encode_roundtrip() {
        let config = json!({"version": "0.4.0-alpha", "process": {"commandLine": "echo hi"}});
        let encoded = encode_config(&config);
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&encoded)
            .unwrap();
        let roundtrip: serde_json::Value = serde_json::from_slice(&decoded).unwrap();
        assert_eq!(config, roundtrip);
    }

    #[test]
    fn shell_join_handles_spaces() {
        let args = vec!["hello world".into(), "simple".into(), "has\"quote".into()];
        let joined = shell_join(&args);
        assert_eq!(joined, r#""hello world" simple "has\"quote""#);
    }
}
