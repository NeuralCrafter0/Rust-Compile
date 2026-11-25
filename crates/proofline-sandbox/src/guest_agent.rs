//! In-guest execution agent for Firecracker microVMs (`virtio-vsock`) and local UDS testing.

use crate::{
    encode_vsock_frame, read_bounded_pipe, read_vsock_frame, ExecutionConfig, ExecutionOutput,
    NetworkPolicy, MAX_CAPTURE_BYTES,
};
use proofline_core::{sanitize_terminal_trace, ProoflineError, Result};
use std::fs;
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// Verifies that no external network interfaces exist inside the guest (only `lo` allowed).
pub fn verify_airgapped_guest_network() -> Result<()> {
    let sys_net = Path::new("/sys/class/net");
    if !sys_net.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(sys_net).map_err(ProoflineError::Io)? {
        let entry = entry.map_err(ProoflineError::Io)?;
        let name = entry.file_name().to_string_lossy().to_string();
        if name != "lo" {
            return Err(ProoflineError::IsolationViolation(format!(
                "Guest network interface '{}' violates air-gapped microVM policy",
                name
            )));
        }
    }
    Ok(())
}

/// Executes a single `ExecutionConfig` inside the guest boundary with strict timeouts and sanitization.
pub fn execute_guest_request(config: &ExecutionConfig) -> Result<ExecutionOutput> {
    if config.network_policy == NetworkPolicy::HermeticProxyOnly {
        return Err(ProoflineError::IsolationViolation(
            "HermeticProxyOnly disallowed inside air-gapped guest agent".to_string(),
        ));
    }
    if config.command.is_empty() || config.timeout_ms == 0 {
        return Err(ProoflineError::ContractUnmet(
            "Guest command must be non-empty and timeout_ms > 0".to_string(),
        ));
    }

    let mut cmd = Command::new(&config.command[0]);
    if config.command.len() > 1 {
        cmd.args(&config.command[1..]);
    }
    if config.working_dir.exists() {
        cmd.current_dir(&config.working_dir);
    }
    cmd.env_clear();
    cmd.env("PATH", "/usr/local/bin:/usr/bin:/bin");
    for (k, v) in &config.env_vars {
        if k.is_empty() || k.contains('=') || k.contains('\0') || v.contains('\0') {
            return Err(ProoflineError::IsolationViolation(format!(
                "Invalid guest env var rejected: {:?}",
                k
            )));
        }
        cmd.env(k, v);
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
                "Guest execution exceeded timeout of {} ms",
                config.timeout_ms
            )));
        }
        thread::sleep(Duration::from_millis(5));
    };

    let duration_ms = start.elapsed().as_millis() as u64;
    let raw_stdout = stdout_handle
        .join()
        .map_err(|_| ProoflineError::Io(std::io::Error::new(std::io::ErrorKind::Other, "stdout panic")))?
        .map_err(ProoflineError::Io)?
        .unwrap_or_default();
    let raw_stderr = stderr_handle
        .join()
        .map_err(|_| ProoflineError::Io(std::io::Error::new(std::io::ErrorKind::Other, "stderr panic")))?
        .map_err(ProoflineError::Io)?
        .unwrap_or_default();

    Ok(ExecutionOutput {
        exit_code: status.code().unwrap_or(-1),
        stdout_blake3: blake3::hash(&raw_stdout).to_hex().to_string(),
        stderr_blake3: blake3::hash(&raw_stderr).to_hex().to_string(),
        stdout: sanitize_terminal_trace(&String::from_utf8_lossy(&raw_stdout)),
        stderr: sanitize_terminal_trace(&String::from_utf8_lossy(&raw_stderr)),
        duration_ms,
    })
}

/// Handles one framed `ExecutionConfig` request and writes the framed `ExecutionOutput` response.
pub fn serve_vsock_stream<S: Read + Write>(stream: &mut S) -> Result<()> {
    let config: ExecutionConfig = read_vsock_frame(stream)?;
    let output = execute_guest_request(&config)?;
    let resp = encode_vsock_frame(&output)?;
    stream.write_all(&resp).map_err(ProoflineError::Io)?;
    stream.flush().map_err(ProoflineError::Io)?;
    Ok(())
}

#[cfg(unix)]
pub fn serve_unix_socket(sock_path: &Path, one_shot: bool) -> Result<()> {
    use std::os::unix::net::UnixListener;
    if sock_path.exists() {
        let _ = fs::remove_file(sock_path);
    }
    let listener = UnixListener::bind(sock_path).map_err(ProoflineError::Io)?;
    for conn in listener.incoming() {
        let mut stream = conn.map_err(ProoflineError::Io)?;
        let _ = serve_vsock_stream(&mut stream);
        if one_shot {
            break;
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn serve_af_vsock(port: u32, check_airgap: bool) -> Result<()> {
    use std::mem;
    use std::os::unix::io::FromRawFd;

    if check_airgap {
        verify_airgapped_guest_network()?;
    }

    unsafe {
        let fd = libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0);
        if fd < 0 {
            return Err(ProoflineError::Io(std::io::Error::last_os_error()));
        }

        let mut addr: libc::sockaddr_vm = mem::zeroed();
        addr.svm_family = libc::AF_VSOCK as libc::sa_family_t;
        addr.svm_port = port;
        addr.svm_cid = libc::VMADDR_CID_ANY;

        let rc = libc::bind(
            fd,
            (&addr as *const libc::sockaddr_vm).cast::<libc::sockaddr>(),
            mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
        );
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            libc::close(fd);
            return Err(ProoflineError::Io(err));
        }

        if libc::listen(fd, 16) < 0 {
            let err = std::io::Error::last_os_error();
            libc::close(fd);
            return Err(ProoflineError::Io(err));
        }

        loop {
            let client_fd = libc::accept(fd, std::ptr::null_mut(), std::ptr::null_mut());
            if client_fd < 0 {
                continue;
            }
            let mut stream = fs::File::from_raw_fd(client_fd);
            let _ = serve_vsock_stream(&mut stream);
        }
    }
}
