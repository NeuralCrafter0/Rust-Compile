//! Isolated Execution Infrastructure for Project Proofline.
//! Manages hardware microVM specifications (Firecracker / KVM), virtio-vsock framing,
//! the in-guest execution agent, and Rootless Podman container boundaries.

pub mod guest_agent;

use base64::Engine as _;
use proofline_core::{sanitize_terminal_trace, ProoflineError, ReproductionWitness, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

pub const MAX_CAPTURE_BYTES: usize = 16 * 1024 * 1024;
const MAX_ENV_PAYLOAD_BYTES: usize = 64 * 1024;
pub const DEFAULT_VSOCK_PORT: u32 = 5050;

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
    #[serde(default)]
    pub read_only_workspace: bool,
    #[serde(default)]
    pub stdin_input: Option<Vec<u8>>,
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
            read_only_workspace: false,
            stdin_input: None,
        }
    }
}

/// Attaches a potentially binary/NUL-containing payload safely to `ExecutionConfig`.
/// Raw bytes go to `stdin_input` and base64 `PROOFLINE_INPUT_PAYLOAD_B64`;
/// `PROOFLINE_INPUT_PAYLOAD` is populated only when valid UTF-8 without NUL bytes.
pub fn attach_input_payload(config: &mut ExecutionConfig, payload: &[u8]) {
    config.stdin_input = Some(payload.to_vec());
    let b64 = base64::engine::general_purpose::STANDARD.encode(payload);
    if b64.len() <= MAX_ENV_PAYLOAD_BYTES {
        config
            .env_vars
            .insert("PROOFLINE_INPUT_PAYLOAD_B64".to_string(), b64);
    }
    if payload.len() <= MAX_ENV_PAYLOAD_BYTES {
        if let Ok(text) = std::str::from_utf8(payload) {
            if !text.contains('\0') {
                config
                    .env_vars
                    .insert("PROOFLINE_INPUT_PAYLOAD".to_string(), text.to_string());
                return;
            }
        }
    }
    config.env_vars.remove("PROOFLINE_INPUT_PAYLOAD");
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

pub fn read_bounded_pipe<R: Read>(mut reader: R, limit: usize) -> std::io::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let n = reader.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        let remaining = limit.saturating_sub(out.len());
        if remaining > 0 {
            let take = n.min(remaining);
            out.extend_from_slice(&chunk[..take]);
        }
    }
    Ok(out)
}

impl SandboxRunner for PodmanSandboxRunner {
    fn execute(&self, config: &ExecutionConfig) -> Result<ExecutionOutput> {
        if self.container_image.is_empty() || self.container_image.starts_with('-') {
            return Err(ProoflineError::IsolationViolation(
                "Invalid container image reference".to_string(),
            ));
        }
        if config.command.is_empty() {
            return Err(ProoflineError::ContractUnmet(
                "Execution command must not be empty".to_string(),
            ));
        }
        if config.timeout_ms == 0 {
            return Err(ProoflineError::ContractUnmet(
                "Execution timeout_ms must be > 0".to_string(),
            ));
        }

        // Validate and canonicalize working directory to prevent mount option injection
        let canonical_workdir = if config.working_dir.exists() {
            config.working_dir.canonicalize().map_err(ProoflineError::Io)?
        } else {
            config.working_dir.clone()
        };
        let host_dir = canonical_workdir.to_string_lossy();
        if host_dir.contains(':') || host_dir.contains('\0') || host_dir.contains('\n') || host_dir.contains('\r') {
            return Err(ProoflineError::IsolationViolation(format!(
                "Unsafe working_dir path rejected: {:?}",
                canonical_workdir
            )));
        }

        let mut cmd = Command::new("podman");
        cmd.arg("run").arg("--rm");
        if config.stdin_input.is_some() {
            cmd.arg("-i");
        }

        // Enforce network isolation (fail closed for unconfigured HermeticProxyOnly)
        match config.network_policy {
            NetworkPolicy::Denied | NetworkPolicy::IsolatedLoopback => {
                cmd.arg("--network=none");
            }
            NetworkPolicy::HermeticProxyOnly => {
                return Err(ProoflineError::IsolationViolation(
                    "HermeticProxyOnly requires an explicit isolated proxy endpoint; refusing host loopback exposure".to_string(),
                ));
            }
        }

        // Enforce resource quotas & container timeout
        let timeout_secs = ((config.timeout_ms + 999) / 1000).max(1);
        cmd.arg(format!("--timeout={}", timeout_secs));
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

        // Validate and set environment variables
        for (k, v) in &config.env_vars {
            if k.is_empty() || k.contains('=') || k.contains('\0') || v.contains('\0') {
                return Err(ProoflineError::IsolationViolation(format!(
                    "Invalid environment variable key/value rejected: {:?}",
                    k
                )));
            }
            cmd.arg("-e").arg(format!("{}={}", k, v));
        }

        // Bind mount working directory (`z` label enables rootless Podman access on SELinux hosts)
        let mount_mode = if config.read_only_workspace { "ro,z" } else { "rw,z" };
        cmd.arg("-v")
            .arg(format!("{}:/workspace:{}", host_dir, mount_mode));
        cmd.arg("-w").arg("/workspace");

        cmd.arg(&self.container_image);
        for c in &config.command {
            if c.contains('\0') {
                return Err(ProoflineError::IsolationViolation(
                    "NUL byte rejected in command argument".to_string(),
                ));
            }
            cmd.arg(c);
        }

        cmd.stdin(if config.stdin_input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

        let start = Instant::now();
        let mut child = cmd.spawn().map_err(ProoflineError::Io)?;

        if let Some(payload) = config.stdin_input.clone() {
            if let Some(mut stdin) = child.stdin.take() {
                thread::spawn(move || {
                    let _ = stdin.write_all(&payload);
                });
            }
        }

        let stdout_pipe = child.stdout.take();
        let stderr_pipe = child.stderr.take();
        let stdout_handle = thread::spawn(move || {
            stdout_pipe
                .map(|r| read_bounded_pipe(r, MAX_CAPTURE_BYTES))
                .transpose()
        });
        let stderr_handle = thread::spawn(move || {
            stderr_pipe
                .map(|r| read_bounded_pipe(r, MAX_CAPTURE_BYTES))
                .transpose()
        });

        let deadline = start + Duration::from_millis(config.timeout_ms);
        let status = loop {
            if let Some(status) = child.try_wait().map_err(ProoflineError::Io)? {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_handle.join();
                let _ = stderr_handle.join();
                return Err(ProoflineError::ResourceExhausted(format!(
                    "Sandbox execution exceeded wall-clock timeout of {} ms",
                    config.timeout_ms
                )));
            }
            thread::sleep(Duration::from_millis(10));
        };

        let duration_ms = start.elapsed().as_millis() as u64;
        let raw_stdout = stdout_handle
            .join()
            .map_err(|_| ProoflineError::Io(std::io::Error::new(std::io::ErrorKind::Other, "stdout reader panicked")))?
            .map_err(ProoflineError::Io)?
            .unwrap_or_default();
        let raw_stderr = stderr_handle
            .join()
            .map_err(|_| ProoflineError::Io(std::io::Error::new(std::io::ErrorKind::Other, "stderr reader panicked")))?
            .map_err(ProoflineError::Io)?
            .unwrap_or_default();

        let stdout_blake3 = blake3::hash(&raw_stdout).to_hex().to_string();
        let stderr_blake3 = blake3::hash(&raw_stderr).to_hex().to_string();

        let stdout = sanitize_terminal_trace(&String::from_utf8_lossy(&raw_stdout));
        let stderr = sanitize_terminal_trace(&String::from_utf8_lossy(&raw_stderr));

        Ok(ExecutionOutput {
            exit_code: status.code().unwrap_or(-1),
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

/// Framed protocol message helpers for `virtio-vsock` host <-> guest IPC (RFC-001 Boundary B2).
pub fn encode_vsock_frame<T: Serialize>(msg: &T) -> Result<Vec<u8>> {
    let payload = serde_json::to_vec(msg)?;
    if payload.len() > MAX_CAPTURE_BYTES {
        return Err(ProoflineError::ResourceExhausted(
            "vsock frame exceeds maximum payload size".to_string(),
        ));
    }
    let len = (payload.len() as u32).to_be_bytes();
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&len);
    out.extend_from_slice(&payload);
    Ok(out)
}

pub fn decode_vsock_frame<T: for<'de> Deserialize<'de>>(frame: &[u8]) -> Result<T> {
    if frame.len() < 4 {
        return Err(ProoflineError::ParseFailure(
            "Truncated vsock frame header".to_string(),
        ));
    }
    let len = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
    if len > MAX_CAPTURE_BYTES {
        return Err(ProoflineError::ResourceExhausted(
            "vsock frame payload length exceeds limit".to_string(),
        ));
    }
    if frame.len() < 4 + len {
        return Err(ProoflineError::ParseFailure(
            "Incomplete vsock frame payload".to_string(),
        ));
    }
    Ok(serde_json::from_slice(&frame[4..4 + len])?)
}

/// Reads an exact length-prefixed frame from a blocking stream without waiting for EOF.
pub fn read_vsock_frame<R: Read, T: for<'de> Deserialize<'de>>(reader: &mut R) -> Result<T> {
    let mut hdr = [0u8; 4];
    reader.read_exact(&mut hdr).map_err(ProoflineError::Io)?;
    let len = u32::from_be_bytes(hdr) as usize;
    if len > MAX_CAPTURE_BYTES {
        return Err(ProoflineError::ResourceExhausted(
            "vsock frame payload length exceeds limit".to_string(),
        ));
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).map_err(ProoflineError::Io)?;
    Ok(serde_json::from_slice(&buf)?)
}

/// Executes Firecracker's host-initiated vsock handshake (`CONNECT <port>\n` -> `OK <port>\n`)
/// and exchanges a framed `ExecutionConfig` -> `ExecutionOutput`.
pub fn run_firecracker_vsock_client<S: Read + Write>(
    stream: &mut S,
    port: u32,
    config: &ExecutionConfig,
) -> Result<ExecutionOutput> {
    let connect_line = format!("CONNECT {}\n", port);
    stream
        .write_all(connect_line.as_bytes())
        .map_err(ProoflineError::Io)?;
    stream.flush().map_err(ProoflineError::Io)?;

    let mut ack = Vec::with_capacity(64);
    let mut byte = [0u8; 1];
    loop {
        stream.read_exact(&mut byte).map_err(ProoflineError::Io)?;
        if byte[0] == b'\n' {
            break;
        }
        ack.push(byte[0]);
        if ack.len() > 128 {
            return Err(ProoflineError::IsolationViolation(
                "Firecracker vsock CONNECT response exceeded maximum length".to_string(),
            ));
        }
    }
    let ack_str = String::from_utf8_lossy(&ack);
    if !ack_str.starts_with("OK ") {
        return Err(ProoflineError::IsolationViolation(format!(
            "Firecracker vsock CONNECT rejected: {:?}",
            ack_str
        )));
    }

    let framed_req = encode_vsock_frame(config)?;
    stream.write_all(&framed_req).map_err(ProoflineError::Io)?;
    stream.flush().map_err(ProoflineError::Io)?;
    read_vsock_frame(stream)
}

/// Hardware-virtualized Firecracker microVM sandbox runner using KVM + `virtio-vsock`.
#[derive(Debug, Clone)]
pub struct FirecrackerSandboxRunner {
    pub firecracker_bin: PathBuf,
    pub kernel_image_path: PathBuf,
    pub rootfs_path: PathBuf,
    pub vcpus: u32,
    pub memory_mb: u32,
}

impl FirecrackerSandboxRunner {
    pub fn new(
        firecracker_bin: impl Into<PathBuf>,
        kernel_image_path: impl Into<PathBuf>,
        rootfs_path: impl Into<PathBuf>,
        vcpus: u32,
        memory_mb: u32,
    ) -> Self {
        Self {
            firecracker_bin: firecracker_bin.into(),
            kernel_image_path: kernel_image_path.into(),
            rootfs_path: rootfs_path.into(),
            vcpus,
            memory_mb,
        }
    }

    /// Fails closed unless `/dev/kvm`, the `firecracker` binary, guest kernel, and rootfs exist.
    pub fn probe_environment(&self) -> Result<()> {
        if !std::path::Path::new("/dev/kvm").exists() {
            return Err(ProoflineError::IsolationViolation(
                "Hardware virtualization unavailable: /dev/kvm missing".to_string(),
            ));
        }
        if !self.firecracker_bin.exists() {
            return Err(ProoflineError::IsolationViolation(format!(
                "Firecracker binary not found at {:?}",
                self.firecracker_bin
            )));
        }
        if !self.kernel_image_path.exists() {
            return Err(ProoflineError::IsolationViolation(format!(
                "Guest kernel image not found at {:?}",
                self.kernel_image_path
            )));
        }
        if !self.rootfs_path.exists() {
            return Err(ProoflineError::IsolationViolation(format!(
                "Guest rootfs image not found at {:?}",
                self.rootfs_path
            )));
        }
        Ok(())
    }
}

impl SandboxRunner for FirecrackerSandboxRunner {
    fn execute(&self, config: &ExecutionConfig) -> Result<ExecutionOutput> {
        self.probe_environment()?;
        if config.network_policy == NetworkPolicy::HermeticProxyOnly {
            return Err(ProoflineError::IsolationViolation(
                "HermeticProxyOnly unsupported inside air-gapped Firecracker guest".to_string(),
            ));
        }
        if config.command.is_empty() || config.timeout_ms == 0 {
            return Err(ProoflineError::ContractUnmet(
                "Invalid execution config for Firecracker microVM".to_string(),
            ));
        }

        let tmp = std::env::temp_dir().join(format!("proofline-fc-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).map_err(ProoflineError::Io)?;
        let vsock_path = tmp.join("vsock.sock");
        let cfg_path = tmp.join("vm_config.json");

        let vm_cfg = FirecrackerVmConfig::new_airgapped_sandbox(
            self.kernel_image_path.to_string_lossy(),
            self.rootfs_path.to_string_lossy(),
            self.vcpus,
            self.memory_mb,
            vsock_path.to_string_lossy(),
        );
        std::fs::write(&cfg_path, serde_json::to_vec_pretty(&vm_cfg)?).map_err(ProoflineError::Io)?;

        let mut child = Command::new(&self.firecracker_bin)
            .arg("--no-api")
            .arg("--config-file")
            .arg(&cfg_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(ProoflineError::Io)?;

        #[cfg(unix)]
        {
            use std::os::unix::net::UnixStream;
            let start = Instant::now();
            let deadline = start + Duration::from_millis(config.timeout_ms);
            let mut stream = loop {
                if let Ok(s) = UnixStream::connect(&vsock_path) {
                    break s;
                }
                if let Some(status) = child.try_wait().map_err(ProoflineError::Io)? {
                    let _ = std::fs::remove_dir_all(&tmp);
                    return Err(ProoflineError::IsolationViolation(format!(
                        "Firecracker exited prematurely with status {} before vsock ready",
                        status
                    )));
                }
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = std::fs::remove_dir_all(&tmp);
                    return Err(ProoflineError::ResourceExhausted(
                        "Firecracker microVM boot timed out waiting for virtio-vsock".to_string(),
                    ));
                }
                thread::sleep(Duration::from_millis(5));
            };

            let _ = stream.set_read_timeout(Some(Duration::from_millis(config.timeout_ms)));
            let _ = stream.set_write_timeout(Some(Duration::from_millis(config.timeout_ms)));
            let result = run_firecracker_vsock_client(&mut stream, DEFAULT_VSOCK_PORT, config);
            let _ = child.kill();
            let _ = child.wait();
            let _ = std::fs::remove_dir_all(&tmp);
            result
        }
        #[cfg(not(unix))]
        {
            let _ = child.kill();
            let _ = child.wait();
            let _ = std::fs::remove_dir_all(&tmp);
            Err(ProoflineError::IsolationViolation(
                "Firecracker virtio-vsock requires a Unix host".to_string(),
            ))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IsolationBackend {
    FirecrackerKvm,
    PodmanRootlessContainer,
}

/// Contingency runner implementing RFC-001 Section 16.1: prefers Firecracker KVM microVMs
/// and emits an explicit `SECURITY_ISOLATION_DOWNGRADED_WARNING` when falling back to rootless Podman.
pub struct AdaptiveSandboxRunner {
    firecracker: Option<FirecrackerSandboxRunner>,
    podman: PodmanSandboxRunner,
    pub selected_backend: IsolationBackend,
    pub security_downgrade_warning: Option<String>,
}

impl AdaptiveSandboxRunner {
    pub fn new(
        firecracker: Option<FirecrackerSandboxRunner>,
        podman_image: impl Into<String>,
    ) -> Self {
        let podman = PodmanSandboxRunner::new(podman_image);
        match firecracker {
            Some(fc) => match fc.probe_environment() {
                Ok(()) => Self {
                    firecracker: Some(fc),
                    podman,
                    selected_backend: IsolationBackend::FirecrackerKvm,
                    security_downgrade_warning: None,
                },
                Err(reason) => Self {
                    firecracker: None,
                    podman,
                    selected_backend: IsolationBackend::PodmanRootlessContainer,
                    security_downgrade_warning: Some(format!(
                        "SECURITY_ISOLATION_DOWNGRADED_WARNING: falling back to rootless Podman ({})",
                        reason
                    )),
                },
            },
            None => Self {
                firecracker: None,
                podman,
                selected_backend: IsolationBackend::PodmanRootlessContainer,
                security_downgrade_warning: Some(
                    "SECURITY_ISOLATION_DOWNGRADED_WARNING: Firecracker not configured; using rootless Podman"
                        .to_string(),
                ),
            },
        }
    }
}

impl SandboxRunner for AdaptiveSandboxRunner {
    fn execute(&self, config: &ExecutionConfig) -> Result<ExecutionOutput> {
        match (&self.firecracker, &self.selected_backend) {
            (Some(fc), IsolationBackend::FirecrackerKvm) => fc.execute(config),
            _ => self.podman.execute(config),
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

    #[test]
    fn test_hermetic_proxy_fails_closed_without_host_loopback_leak() {
        let runner = PodmanSandboxRunner::new("docker.io/library/alpine:latest");
        let mut config = ExecutionConfig::default();
        config.network_policy = NetworkPolicy::HermeticProxyOnly;
        config.working_dir = PathBuf::from("/tmp");

        let res = runner.execute(&config);
        assert!(matches!(res, Err(ProoflineError::IsolationViolation(_))));
    }

    #[test]
    fn test_rejects_flag_injection_and_mount_delimiter() {
        let bad_image_runner = PodmanSandboxRunner::new("--privileged");
        let mut config = ExecutionConfig::default();
        config.working_dir = PathBuf::from("/tmp");
        assert!(matches!(
            bad_image_runner.execute(&config),
            Err(ProoflineError::IsolationViolation(_))
        ));

        let runner = PodmanSandboxRunner::new("docker.io/library/alpine:latest");
        config.working_dir = PathBuf::from("/tmp/bad:mount");
        assert!(matches!(
            runner.execute(&config),
            Err(ProoflineError::IsolationViolation(_))
        ));
    }

    #[test]
    fn test_binary_nul_payload_attaches_safely() {
        let mut config = ExecutionConfig::default();
        attach_input_payload(&mut config, b"\x00\xff\xfeCRASH");
        assert_eq!(
            config.stdin_input.as_deref(),
            Some(b"\x00\xff\xfeCRASH".as_slice())
        );
        assert!(config.env_vars.contains_key("PROOFLINE_INPUT_PAYLOAD_B64"));
        assert!(!config.env_vars.contains_key("PROOFLINE_INPUT_PAYLOAD"));

        attach_input_payload(&mut config, b"GET ../../etc/passwd HTTP/1.1");
        assert_eq!(
            config.env_vars.get("PROOFLINE_INPUT_PAYLOAD").map(String::as_str),
            Some("GET ../../etc/passwd HTTP/1.1")
        );
    }

    #[test]
    fn test_vsock_frame_and_adaptive_fallback_warning() {
        let cfg = ExecutionConfig::default();
        let framed = encode_vsock_frame(&cfg).unwrap();
        let decoded: ExecutionConfig = decode_vsock_frame(&framed).unwrap();
        assert_eq!(decoded.timeout_ms, cfg.timeout_ms);

        let fc = FirecrackerSandboxRunner::new(
            "/nonexistent/firecracker",
            "/nonexistent/vmlinux",
            "/nonexistent/rootfs.ext4",
            1,
            512,
        );
        assert!(matches!(
            fc.probe_environment(),
            Err(ProoflineError::IsolationViolation(_))
        ));

        let adaptive = AdaptiveSandboxRunner::new(Some(fc), "docker.io/library/alpine:latest");
        assert_eq!(
            adaptive.selected_backend,
            IsolationBackend::PodmanRootlessContainer
        );
        assert!(adaptive
            .security_downgrade_warning
            .as_deref()
            .unwrap()
            .contains("SECURITY_ISOLATION_DOWNGRADED_WARNING"));
    }

    #[cfg(unix)]
    #[test]
    fn test_firecracker_vsock_handshake_and_guest_agent_roundtrip() {
        use std::os::unix::net::UnixStream;

        let (mut host_side, mut guest_bridge) = UnixStream::pair().unwrap();

        let server = thread::spawn(move || {
            // Simulate Firecracker's host-initiated `CONNECT <port>\n` -> `OK <port>\n` bridge
            let mut line = Vec::new();
            let mut b = [0u8; 1];
            loop {
                guest_bridge.read_exact(&mut b).unwrap();
                if b[0] == b'\n' {
                    break;
                }
                line.push(b[0]);
            }
            assert_eq!(String::from_utf8_lossy(&line), "CONNECT 5050");
            guest_bridge.write_all(b"OK 10000\n").unwrap();
            guest_bridge.flush().unwrap();

            guest_agent::serve_vsock_stream(&mut guest_bridge).unwrap();
        });

        let mut cfg = ExecutionConfig::default();
        cfg.working_dir = PathBuf::from("/tmp");
        cfg.command = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "printf 'guest-ok\\x1b[31m\\n'".to_string(),
        ];

        let out = run_firecracker_vsock_client(&mut host_side, DEFAULT_VSOCK_PORT, &cfg).unwrap();
        assert_eq!(out.exit_code, 0);
        assert_eq!(out.stdout, "guest-ok\n");
        server.join().unwrap();
    }
}
