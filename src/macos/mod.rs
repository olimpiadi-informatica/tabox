// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0
//! This module contains the sandbox for MacOS

use std::fs::{metadata, set_permissions, File, Permissions};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::Context;
use libproc::libproc::proc_pid::pidinfo;
use libproc::libproc::task_info::TaskInfo;
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;

use crate::configuration::SandboxConfiguration;
use crate::result::{ExitStatus, ResourceUsage, SandboxExecutionResult};
use crate::util::{setup_resource_limits, start_wall_time_watcher, wait};
use crate::{Result, Sandbox};

pub struct MacOSSandbox {
    child: Child,
    start_time: Instant,
    killed: Arc<AtomicBool>,
}

impl Sandbox for MacOSSandbox {
    fn run(config: SandboxConfiguration) -> Result<Self> {
        let mut command = Command::new(&config.executable);

        unsafe {
            let config = config.clone();

            // This code get executed after the fork() and before the exec()
            command.pre_exec(move || {
                setup_resource_limits(&config).expect("Error setting resource limits");
                Ok(())
            });
        }

        command
            .args(config.args)
            .env_clear()
            .envs(config.env)
            .current_dir(&config.working_directory);

        if let Some(stdin) = &config.stdin {
            let stdin = File::open(stdin)
                .with_context(|| format!("Failed to open stdin file at {}", stdin.display()))?;
            command.stdin(stdin);
        }

        if let Some(stdout) = &config.stdout {
            let stdout = File::create(stdout)
                .with_context(|| format!("Failed to open stdout file at {}", stdout.display()))?;
            command.stdout(stdout);
        }

        if let Some(stderr) = &config.stderr {
            let stderr = File::create(stderr)
                .with_context(|| format!("Failed to open stderr file at {}", stderr.display()))?;
            command.stderr(stderr);
        }

        for mount in &config.mount_paths {
            let is_inside_sandbox = mount.target.starts_with(&config.working_directory);
            let is_nested = config
                .mount_paths
                .iter()
                .any(|m| mount.target != m.target && mount.target.starts_with(&m.target));
            if is_inside_sandbox && is_nested {
                let parent = mount.target.parent().with_context(|| {
                    format!("Invalid mount directory {}", mount.target.display())
                })?;
                let permissions = metadata(parent)
                    .with_context(|| {
                        format!("Failed to mount directory {}", mount.target.display())
                    })?
                    .permissions();
                set_permissions(&parent, Permissions::from_mode(0o700)).with_context(|| {
                    format!("Failed to mount directory {}", mount.target.display())
                })?;
                symlink(&mount.source, &mount.target).with_context(|| {
                    format!("Failed to mount directory {}", mount.target.display())
                })?;
                set_permissions(&parent, permissions)?;
            }
        }

        // Spawn child
        let child = command.spawn().context("Failed to spawn command")?;

        let killed = Arc::new(AtomicBool::new(false));
        let child_pid = child.id() as i32;

        // This thread monitors the resources used by the process and kills it when the limit is exceeded
        thread::Builder::new()
            .name("TABox resource watcher".into())
            .spawn(move || loop {
                match has_exceeded_resources(child_pid, config.time_limit, config.memory_limit) {
                    ResourceCheckResult::Exceeded => {
                        // Send SIGSEGV since it's the same that Linux sends.
                        kill(Pid::from_raw(child_pid), Signal::SIGSEGV)
                            .expect("Error killing child");
                    }
                    ResourceCheckResult::ProcessGone => return,
                    ResourceCheckResult::Ok => {}
                }

                thread::sleep(Duration::from_millis(5));
            })
            .context("Failed to start watcher thread")?;

        if let Some(limit) = config.wall_time_limit {
            start_wall_time_watcher(limit, child_pid, killed.clone())?;
        }

        Ok(MacOSSandbox {
            child,
            start_time: Instant::now(),
            killed,
        })
    }

    fn wait(self) -> Result<SandboxExecutionResult> {
        // Wait child for completion
        let (status, resource_usage) =
            wait(self.child.id() as libc::pid_t).context("Failed to wait")?;

        Ok(SandboxExecutionResult {
            status: if self.killed.load(Ordering::SeqCst) {
                ExitStatus::Killed
            } else {
                status
            },
            resource_usage: ResourceUsage {
                wall_time_usage: (Instant::now() - self.start_time).as_secs_f64(),
                memory_usage: resource_usage.memory_usage / 1024, // on macOS memory usage is in bytes!
                ..resource_usage
            },
        })
    }

    fn is_secure() -> bool {
        false
    }
}

enum ResourceCheckResult {
    Ok,
    Exceeded,
    ProcessGone,
}

fn has_exceeded_resources(
    pid: i32,
    time_limit: Option<u64>,
    memory_limit: Option<u64>,
) -> ResourceCheckResult {
    let task_info = match pidinfo::<TaskInfo>(pid, 0) {
        Ok(info) => info,
        Err(err) => {
            if err.contains("No such process") {
                return ResourceCheckResult::ProcessGone;
            }
            panic!("Failed to get task info: {}", err)
        }
    };

    if let Some(time_limit) = time_limit {
        // pti_total_user is in nanoseconds
        if task_info.pti_total_user / 1_000_000_000 >= time_limit {
            return ResourceCheckResult::Exceeded;
        }
    }

    if let Some(memory_limit) = memory_limit {
        if task_info.pti_resident_size > memory_limit {
            return ResourceCheckResult::Exceeded;
        }
    }

    ResourceCheckResult::Ok
}
