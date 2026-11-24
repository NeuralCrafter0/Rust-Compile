use proofline_core::ProoflineError;
use proofline_intelligence::{BuildSystemKind, IngestionEngine};
use std::fs::{self, File};
use std::io::Write;
use tempfile::tempdir;

#[test]
fn test_malicious_makefile_does_not_execute() {
    let dir = tempdir().unwrap();
    let marker_file = dir.path().join("SHOULD_NOT_EXIST.txt");

    // Craft a hostile Makefile that attempts to delete root or write marker
    let makefile_path = dir.path().join("Makefile");
    let mut file = File::create(makefile_path).unwrap();
    writeln!(
        file,
        "all:\n\ttouch {}\n\trm -rf / 2>/dev/null || true",
        marker_file.display()
    )
    .unwrap();

    let engine = IngestionEngine::default();
    let inspection = engine.inspect_repository(dir.path()).unwrap();

    // Verify build system was detected statically
    assert!(inspection.build_systems.contains(&BuildSystemKind::Makefile));

    // Verify the command NEVER ran on the host
    assert!(!marker_file.exists(), "Host isolation violated! Malicious Makefile was executed!");
}

#[test]
fn test_resource_exhaustion_on_too_many_files() {
    let dir = tempdir().unwrap();
    // Configure engine with maximum 5 files
    let engine = IngestionEngine::new(1024 * 1024, 1024 * 1024, 5);

    for i in 0..10 {
        let file_path = dir.path().join(format!("file_{}.txt", i));
        File::create(file_path).unwrap();
    }

    let result = engine.inspect_repository(dir.path());
    assert!(result.is_err());
    match result {
        Err(ProoflineError::ResourceExhausted(msg)) => {
            assert!(msg.contains("file count limit"));
        }
        other => panic!("Expected ResourceExhausted, got: {:?}", other),
    }
}

#[test]
fn test_symlink_escape_to_sensitive_path_rejected() {
    let dir = tempdir().unwrap();
    let repo_dir = dir.path().join("untrusted_repo");
    fs::create_dir(&repo_dir).unwrap();

    #[cfg(unix)]
    {
        let malicious_link = repo_dir.join("etc_passwd_link");
        std::os::unix::fs::symlink("/etc/passwd", malicious_link).unwrap();

        let engine = IngestionEngine::default();
        let result = engine.inspect_repository(&repo_dir);

        assert!(result.is_err());
        match result {
            Err(ProoflineError::IsolationViolation(msg)) => {
                assert!(msg.contains("Symlink traversal"));
            }
            other => panic!("Expected IsolationViolation, got: {:?}", other),
        }
    }
}
