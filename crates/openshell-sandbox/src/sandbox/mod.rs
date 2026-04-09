// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Platform sandboxing implementation.

use crate::policy::SandboxPolicy;
use miette::Result;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "windows")]
pub mod windows;

/// Apply sandboxing rules for the current platform.
///
/// On Linux, this applies Landlock filesystem restrictions and seccomp syscall
/// filters. On Windows, containment is handled at process creation time via MXC
/// AppContainer (see [`windows`] module) — this function logs the sandbox state.
/// On other platforms, a warning is emitted.
///
/// # Errors
///
/// Returns an error if the sandbox cannot be applied.
#[cfg_attr(
    not(any(target_os = "linux", target_os = "windows")),
    allow(clippy::unnecessary_wraps)
)]
pub fn apply(policy: &SandboxPolicy, workdir: Option<&str>) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        linux::apply(policy, workdir)
    }

    // On Windows, Landlock/seccomp don't exist. Containment is applied at
    // process spawn time via MXC's wxc-exec (AppContainer). This branch
    // logs the policy state for observability.
    #[cfg(target_os = "windows")]
    {
        let _ = workdir;
        if windows::find_wxc_exec().is_some() {
            openshell_ocsf::ocsf_emit!(
                openshell_ocsf::ConfigStateChangeBuilder::new(crate::ocsf_ctx())
                    .severity(openshell_ocsf::SeverityId::Informational)
                    .status(openshell_ocsf::StatusId::Success)
                    .state(openshell_ocsf::StateId::Enabled, "applying")
                    .message(format!(
                        "MXC AppContainer sandbox active [fs_ro:{} fs_rw:{} net:{:?}]",
                        policy.filesystem.read_only.len(),
                        policy.filesystem.read_write.len(),
                        policy.network.mode,
                    ))
                    .build()
            );
        } else {
            openshell_ocsf::ocsf_emit!(
                openshell_ocsf::DetectionFindingBuilder::new(crate::ocsf_ctx())
                    .activity(openshell_ocsf::ActivityId::Open)
                    .severity(openshell_ocsf::SeverityId::High)
                    .finding_info(openshell_ocsf::FindingInfo::new(
                        "mxc-wxc-exec-not-found",
                        "MXC Binary Not Found",
                    ).with_desc(
                        "wxc-exec.exe not found; Windows sandbox will be inactive. \
                         Set OPENSHELL_WXC_EXEC_PATH or add wxc-exec.exe to PATH."
                    ))
                    .message("wxc-exec.exe not found — sandbox inactive")
                    .build()
            );
        }
        Ok(())
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        let _ = (policy, workdir);
        openshell_ocsf::ocsf_emit!(
            openshell_ocsf::DetectionFindingBuilder::new(crate::ocsf_ctx())
                .activity(openshell_ocsf::ActivityId::Open)
                .severity(openshell_ocsf::SeverityId::Medium)
                .finding_info(openshell_ocsf::FindingInfo::new(
                    "platform-sandbox-unavailable",
                    "Platform Sandboxing Not Implemented",
                ).with_desc("Sandbox policy provided but platform sandboxing is not yet implemented on this OS"))
                .message("Platform sandboxing not yet implemented")
                .build()
        );
        Ok(())
    }
}
