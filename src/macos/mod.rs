// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0
//! This module contains the sandbox for MacOS

use std::fs::File;
use std::mem::MaybeUninit;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::Context;
use libc::mach_task_self;
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
            .current_dir(config.working_directory);

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

        // Spawn child
        let child = command.spawn().context("Failed to spawn command")?;

        let killed = Arc::new(AtomicBool::new(false));
        let child_pid = child.id() as i32;

        // This thread monitors the resources used by the process and kills it when the limit is exceeded
        thread::Builder::new()
            .name("TABox resource watcher".into())
            .spawn(move || {
                let task = {
                    let mut task: libc::mach_port_t = Default::default();
                    let result =
                        unsafe { libc::task_for_pid(mach_task_self(), child_pid, &mut task) };

                    if result != libc::KERN_SUCCESS {
                        panic!("Failed to get task port");
                    }

                    task
                };

                loop {
                    if has_exceeded_resources(task, config.time_limit, config.memory_limit) {
                        // Send SIGSEGV since it's the same that Linux sends.
                        kill(Pid::from_raw(child_pid), Signal::SIGSEGV)
                            .expect("Error killing child");
                    }

                    thread::sleep(Duration::from_millis(5));
                }
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

fn has_exceeded_resources(
    task: libc::mach_port_t,
    time_limit: Option<u64>,
    memory_limit: Option<u64>,
) -> bool {
    let mut task_info = MaybeUninit::<libc::mach_task_basic_info_data_t>::uninit();
    let mut count = libc::MACH_TASK_BASIC_INFO_COUNT;

    let result = unsafe {
        libc::task_info(
            task,
            libc::MACH_TASK_BASIC_INFO,
            task_info.as_mut_ptr() as libc::task_info_t,
            &mut count as *mut libc::mach_msg_type_number_t,
        )
    };

    if result != libc::KERN_SUCCESS {
        panic!("Failed to get task info");
    }

    let task_info = unsafe { task_info.assume_init() };

    if let Some(time_limit) = time_limit {
        if task_info.user_time.seconds as u64 >= time_limit {
            return true;
        }
    }

    if let Some(memory_limit) = memory_limit {
        if task_info.resident_size_max > memory_limit {
            return true;
        }
    }

    false
}
