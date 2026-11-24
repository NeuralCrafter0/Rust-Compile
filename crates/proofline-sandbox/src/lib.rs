//! Isolated Execution Infrastructure for Project Proofline.
//! Manages hardware microVM specifications (Firecracker / KVM) and
//! Rootless Podman container boundaries with fail-closed network policies.

use proofline_core::{ProoflineError, ReproductionWitness, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Instant;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NetworkPolicy {
    Denied,
    HermeticProxyOnly,
    IsolatedLoopback,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionConfig {
    pub command: Vec<String>,
    pub working_dir: PathBuf,
    pub env_vars: BTreeMap<String, String>,
    pub timeout_ms: u64,
    pub memory_limit_mb: u64,
    pub cpu_limit_cores: f32,
    pub network_policy: NetworkPolicy,
    pub read_only_rootfs: bool,
}

impl Default for ExecutionConfig {
    fn default() -> Self {
        Self {
            command: vec!["/bin/sh".to_string(), "-c".to_string(), "exit 0".to_string()],
            working_dir: PathBuf::from("/workspace"),
            env_vars: BTreeMap::new(),
            timeout_ms: 30_000,
            memory_limit_mb: 1024,
            cpu_limit_cores: 1.0,
            network_policy: NetworkPolicy::Denied,
            read_only_rootfs: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionOutput {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u64,
    pub stdout_blake3: String,
    pub stderr_blake3: String,
}

/// Abstract contract for isolated sandbox runners.
pub trait SandboxRunner: Send + Sync {
    fn execute(&self, config: &ExecutionConfig) -> Result<ExecutionOutput>;
}

/// Rootless container runner utilizing Linux cgroups v2 and seccomp.
pub struct PodmanSandboxRunner {
    container_image: String,
}

impl PodmanSandboxRunner {
    pub fn new(image: impl Into<String>) -> Self {
        Self {
            container_image: image.into(),
        }
    }
}

impl SandboxRunner for PodmanSandboxRunner {
    fn execute(&self, config: &ExecutionConfig) -> Result<ExecutionOutput> {
        let mut cmd = Command::new("podman");
        cmd.arg("run").arg("--rm");

        // Enforce network isolation
        match config.network_policy {
            NetworkPolicy::Denied => {
                cmd.arg("--network=none");
            }
            NetworkPolicy::IsolatedLoopback => {
                cmd.arg("--network=none");
            }
            NetworkPolicy::HermeticProxyOnly => {
                cmd.arg("--network=slirp4netns:allow_host_loopback=true");
            }
        }

        // Enforce resource quotas
        cmd.arg(format!("--memory={}m", config.memory_limit_mb));
        cmd.arg(format!("--cpus={}", config.cpu_limit_cores));
        cmd.arg("--pids-limit=256");

        // Enforce security boundaries
        cmd.arg("--cap-drop=ALL");
        cmd.arg("--security-opt=no-new-privileges");
        if config.read_only_rootfs {
            cmd.arg("--read-only");
            cmd.arg("--tmpfs=/tmp:rw,noexec,nosuid,size=128m");
        }

        // Set environment variables
        for (k, v) in &config.env_vars {
            cmd.arg("-e").arg(format!("{}={}", k, v));
        }

        // Bind mount working directory
        let host_dir = config.working_dir.to_string_lossy();
        cmd.arg("-v").arg(format!("{}:/workspace:rw", host_dir));
        cmd.arg("-w").arg("/workspace");

        cmd.arg(&self.container_image);
        for c in &config.command {
            cmd.arg(c);
        }

        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

        let start = Instant::now();
        let child = cmd.spawn().map_err(ProoflineError::Io)?;
        let output = child
            .wait_with_output()
            .map_err(ProoflineError::Io)?;
        let duration_ms = start.elapsed().as_millis() as u64;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        let stdout_blake3 = blake3::hash(output.stdout.as_slice()).to_hex().to_string();
        let stderr_blake3 = blake3::hash(output.stderr.as_slice()).to_hex().to_string();

        Ok(ExecutionOutput {
            exit_code: output.status.code().unwrap_or(-1),
            stdout,
            stderr,
            duration_ms,
            stdout_blake3,
            stderr_blake3,
        })
    }
}

/// Firecracker MicroVM JSON configuration builder.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirecrackerVmConfig {
    pub boot_source: FirecrackerBootSource,
    pub drives: Vec<FirecrackerDrive>,
    pub machine_config: FirecrackerMachineConfig,
    pub vsock: Option<FirecrackerVsock>,
    pub network_interfaces: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirecrackerBootSource {
    pub kernel_image_path: String,
    pub boot_args: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirecrackerDrive {
    pub drive_id: String,
    pub path_on_host: String,
    pub is_root_device: bool,
    pub is_read_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirecrackerMachineConfig {
    pub vcpu_count: u32,
    pub mem_size_mib: u32,
    pub smt: bool,
    pub track_dirty_pages: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirecrackerVsock {
    pub vsock_id: String,
    pub guest_cid: u32,
    pub uds_path: String,
}

impl FirecrackerVmConfig {
    pub fn new_airgapped_sandbox(
        kernel_path: impl Into<String>,
        rootfs_path: impl Into<String>,
        vcpus: u32,
        memory_mb: u32,
        vsock_socket_path: impl Into<String>,
    ) -> Self {
        Self {
            boot_source: FirecrackerBootSource {
                kernel_image_path: kernel_path.into(),
                boot_args: "console=ttyS0 reboot=k panic=1 pci=off quiet".to_string(),
            },
            drives: vec![FirecrackerDrive {
                drive_id: "rootfs".to_string(),
                path_on_host: rootfs_path.into(),
                is_root_device: true,
                is_read_only: true, // Immutable base image
            }],
            machine_config: FirecrackerMachineConfig {
                vcpu_count: vcpus,
                mem_size_mib: memory_mb,
                smt: false,
                track_dirty_pages: false,
            },
            vsock: Some(FirecrackerVsock {
                vsock_id: "vsock0".to_string(),
                guest_cid: 3,
                uds_path: vsock_socket_path.into(),
            }),
            network_interfaces: Vec::new(), // Denied by design: ZERO network devices attached
        }
    }
}

/// N-run deterministic reproducer harness.
pub struct DeterministicReplayVerifier;

impl DeterministicReplayVerifier {
    pub fn verify_reproducer<R: SandboxRunner>(
        runner: &R,
        config: &ExecutionConfig,
        required_runs: u32,
    ) -> Result<ReproductionWitness> {
        if required_runs < 1 {
            return Err(ProoflineError::ContractUnmet(
                "Required reproduction runs must be >= 1".to_string(),
            ));
        }

        let mut baseline_exit: Option<i32> = None;
        let mut baseline_stderr_hash: Option<String> = None;
        let mut successful_runs = 0u32;
        let mut total_duration = 0u64;

        for _ in 0..required_runs {
            let output = runner.execute(config)?;
            total_duration += output.duration_ms;

            if let Some(expected_exit) = baseline_exit {
                if output.exit_code == expected_exit {
                    successful_runs += 1;
                }
            } else {
                baseline_exit = Some(output.exit_code);
                baseline_stderr_hash = Some(output.stderr_blake3.clone());
                successful_runs += 1;
            }
        }

        let is_deterministic = successful_runs == required_runs;
        let exit_code = baseline_exit.unwrap_or(-1);
        let fault_signal = if exit_code != 0 {
            format!("EXIT_CODE_{}", exit_code)
        } else {
            "CLEAN_EXIT_0".to_string()
        };

        Ok(ReproductionWitness {
            deterministic: is_deterministic,
            successful_runs,
            total_attempted_runs: required_runs,
            input_artifact_blake3: blake3::hash(config.command.join(" ").as_bytes())
                .to_hex()
                .to_string(),
            fault_signal_or_oracle: fault_signal,
            execution_trace_blake3: baseline_stderr_hash.unwrap_or_default(),
            execution_duration_ms: total_duration / required_runs as u64,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_firecracker_config_has_no_network() {
        let config = FirecrackerVmConfig::new_airgapped_sandbox(
            "/path/to/vmlinux",
            "/path/to/rootfs.ext4",
            2,
            1024,
            "/tmp/vsock.sock",
        );
        assert!(config.network_interfaces.is_empty());
        assert_eq!(config.machine_config.vcpu_count, 2);
        assert!(config.drives[0].is_read_only);
    }
}
