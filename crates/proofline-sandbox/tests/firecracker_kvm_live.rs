use proofline_sandbox::{ExecutionConfig, FirecrackerSandboxRunner, NetworkPolicy, SandboxRunner};
use std::env;
use std::path::PathBuf;

/// Live end-to-end KVM verification against real Firecracker v1.18.0 + Linux vmlinux-6.1.102 + ext4 rootfs.
/// Runs when host KVM & provisioned Firecracker artifacts exist (skipped gracefully in unprivileged containers).
#[test]
fn test_live_firecracker_kvm_microvm_vsock_roundtrip() {
    let home = match env::var("HOME") {
        Ok(h) => PathBuf::from(h),
        Err(_) => return,
    };
    let fc_dir = home.join(".local/share/proofline/firecracker");
    let fc_bin = fc_dir.join("firecracker");
    let kernel = fc_dir.join("vmlinux-6.1.102");
    let rootfs = fc_dir.join("rootfs.ext4");

    if !PathBuf::from("/dev/kvm").exists() || !fc_bin.exists() || !kernel.exists() || !rootfs.exists() {
        eprintln!(
            "Skipping live Firecracker KVM test (requires /dev/kvm and artifacts under {:?})",
            fc_dir
        );
        return;
    }

    let runner = FirecrackerSandboxRunner::new(&fc_bin, &kernel, &rootfs, 1, 256);

    // 1. Verify command execution inside real guest kernel + air-gapped network (`lo` only)
    let mut cfg = ExecutionConfig::default();
    cfg.working_dir = PathBuf::from("/tmp");
    cfg.timeout_ms = 10_000;
    cfg.network_policy = NetworkPolicy::Denied;
    cfg.command = vec![
        "/bin/sh".to_string(),
        "-c".to_string(),
        "uname -s -r && ls -1 /sys/class/net && printf 'fc-ok\\x1b[31m\\n'".to_string(),
    ];

    let out = runner
        .execute(&cfg)
        .expect("real Firecracker KVM microVM execution");
    assert_eq!(out.exit_code, 0, "stderr: {}", out.stderr);
    assert!(out.stdout.contains("Linux 6.1.102"), "stdout: {}", out.stdout);
    assert!(out.stdout.contains("fc-ok\n"), "ANSI sequence must be sanitized: {}", out.stdout);
    assert!(!out.stdout.contains('\x1b'));
    // Guest must only have loopback interface `lo`
    let net_ifaces: Vec<&str> = out
        .stdout
        .lines()
        .skip(1)
        .take_while(|l| *l != "fc-ok")
        .collect();
    assert_eq!(net_ifaces, vec!["lo"], "unexpected guest network interfaces: {:?}", net_ifaces);

    // 2. Verify non-zero fault propagation over virtio-vsock and immutable `/` read-only rootfs
    let mut fault_cfg = ExecutionConfig::default();
    fault_cfg.working_dir = PathBuf::from("/tmp");
    fault_cfg.timeout_ms = 10_000;
    fault_cfg.command = vec![
        "/bin/sh".to_string(),
        "-c".to_string(),
        "touch /immutable_probe 2>/dev/null; echo ro_status=$?; exit 42".to_string(),
    ];
    let fault_out = runner
        .execute(&fault_cfg)
        .expect("second sequential Firecracker KVM microVM execution");
    assert_eq!(fault_out.exit_code, 42);
    assert!(fault_out.stdout.contains("ro_status=1"), "rootfs must be read-only: {}", fault_out.stdout);

    // 3. Verify host -> guest workspace staging & `/workspace/...` argument mapping over vsock
    let host_ws = std::env::temp_dir().join(format!("proofline-kvm-ws-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&host_ws);
    std::fs::create_dir_all(&host_ws).unwrap();
    let script_path = host_ws.join("probe.sh");
    std::fs::write(&script_path, "#!/bin/sh\necho staged_ok:$(cat input.txt)\n").unwrap();
    std::fs::write(host_ws.join("input.txt"), "kvm-ws-data").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    let mut staged_cfg = ExecutionConfig::default();
    staged_cfg.working_dir = host_ws.clone();
    staged_cfg.timeout_ms = 10_000;
    staged_cfg.command = vec!["/workspace/probe.sh".to_string()];
    let staged_out = runner
        .execute(&staged_cfg)
        .expect("staged workspace Firecracker KVM execution");
    let _ = std::fs::remove_dir_all(&host_ws);
    assert_eq!(staged_out.exit_code, 0, "stderr: {}", staged_out.stderr);
    assert!(
        staged_out.stdout.contains("staged_ok:kvm-ws-data"),
        "expected staged guest output, got: {}",
        staged_out.stdout
    );
}
