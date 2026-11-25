//! Software Intelligence Layer for Project Proofline.
//! Ingestion, multi-language detection, safe manifest inspection,
//! and path-traversal/symlink attack defense.

use proofline_core::{ProoflineError, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use walkdir::WalkDir;

/// Supported project language ecosystems.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProjectLanguage {
    C,
    Cpp,
    Rust,
    Python,
    JavaScript,
    TypeScript,
    Go,
    Java,
    Unknown,
}

/// Discovered build system.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BuildSystemKind {
    Cargo,
    CMake,
    Makefile,
    Npm,
    PythonPip,
    Unknown,
}

/// Manifest and dependency metadata safely extracted without script execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectInspection {
    pub primary_language: ProjectLanguage,
    pub detected_languages: Vec<ProjectLanguage>,
    pub build_systems: Vec<BuildSystemKind>,
    pub total_source_files: usize,
    pub total_size_bytes: u64,
    pub manifest_dependencies: BTreeMap<String, String>,
    pub root_hash_blake3: String,
    #[serde(default)]
    pub detected_frameworks: Vec<String>,
    #[serde(default)]
    pub git_head_commit: Option<String>,
}

pub struct IngestionEngine {
    max_file_size_bytes: u64,
    max_total_size_bytes: u64,
    max_total_files: usize,
}

impl Default for IngestionEngine {
    fn default() -> Self {
        Self {
            max_file_size_bytes: 10 * 1024 * 1024,      // 10 MB per file limit
            max_total_size_bytes: 500 * 1024 * 1024,   // 500 MB total repo limit
            max_total_files: 50_000,
        }
    }
}

impl IngestionEngine {
    pub fn new(max_file_size: u64, max_total_size: u64, max_files: usize) -> Self {
        Self {
            max_file_size_bytes: max_file_size,
            max_total_size_bytes: max_total_size,
            max_total_files: max_files,
        }
    }

    /// Safely inspects a repository directory, rejecting symlink escapes and zip bombs.
    pub fn inspect_repository<P: AsRef<Path>>(&self, repo_dir: P) -> Result<ProjectInspection> {
        let repo_path = repo_dir.as_ref();
        if !repo_path.exists() || !repo_path.is_dir() {
            return Err(ProoflineError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Repository path not found: {:?}", repo_path),
            )));
        }

        let canonical_root = repo_path.canonicalize().map_err(ProoflineError::Io)?;
        let mut total_files = 0;
        let mut total_size = 0u64;
        let mut detected_languages = Vec::new();
        let mut build_systems = Vec::new();
        let mut manifest_dependencies = BTreeMap::new();
        let mut repo_hasher = blake3::Hasher::new();

        for entry in WalkDir::new(&canonical_root)
            .follow_links(false)
            .sort_by_file_name()
        {
            let entry = entry.map_err(|e| ProoflineError::ParseFailure(e.to_string()))?;
            let path = entry.path();

            // Fail-closed defense against Symlink Traversal (including dangling symlinks)
            if entry.path_is_symlink() {
                Self::validate_symlink_target(path, &canonical_root)?;
                continue;
            }

            if entry.file_type().is_file() {
                total_files += 1;
                if total_files > self.max_total_files {
                    return Err(ProoflineError::ResourceExhausted(format!(
                        "Repository exceeds file count limit of {}",
                        self.max_total_files
                    )));
                }

                // Open the file once and check metadata on the open handle to prevent TOCTOU swaps
                let file = File::open(path).map_err(ProoflineError::Io)?;
                let meta = file.metadata().map_err(ProoflineError::Io)?;
                if !meta.is_file() {
                    return Err(ProoflineError::IsolationViolation(format!(
                        "Non-regular file encountered at {:?}",
                        path
                    )));
                }
                let file_size = meta.len();
                if file_size > self.max_file_size_bytes {
                    return Err(ProoflineError::ResourceExhausted(format!(
                        "File {:?} exceeds maximum allowed size ({} bytes)",
                        path, file_size
                    )));
                }

                // Stream actual content bounded by max_file_size_bytes + 1 (TOCTOU guard)
                let mut file_hasher = blake3::Hasher::new();
                let mut reader = file.take(self.max_file_size_bytes + 1);
                let mut buf = [0u8; 16 * 1024];
                let mut actual_size = 0u64;
                loop {
                    let n = reader.read(&mut buf).map_err(ProoflineError::Io)?;
                    if n == 0 {
                        break;
                    }
                    actual_size += n as u64;
                    if actual_size > self.max_file_size_bytes {
                        return Err(ProoflineError::ResourceExhausted(format!(
                            "File {:?} grew past maximum allowed size ({} bytes)",
                            path, self.max_file_size_bytes
                        )));
                    }
                    file_hasher.update(&buf[..n]);
                }

                total_size += actual_size;
                if total_size > self.max_total_size_bytes {
                    return Err(ProoflineError::ResourceExhausted(format!(
                        "Repository total size exceeds limit of {} bytes",
                        self.max_total_size_bytes
                    )));
                }

                // Detect Language and Build Systems
                let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");

                match ext {
                    "c" | "h" => push_unique(&mut detected_languages, ProjectLanguage::C),
                    "cpp" | "cc" | "cxx" | "hpp" => push_unique(&mut detected_languages, ProjectLanguage::Cpp),
                    "rs" => push_unique(&mut detected_languages, ProjectLanguage::Rust),
                    "py" => push_unique(&mut detected_languages, ProjectLanguage::Python),
                    "js" | "mjs" | "cjs" => push_unique(&mut detected_languages, ProjectLanguage::JavaScript),
                    "ts" | "tsx" => push_unique(&mut detected_languages, ProjectLanguage::TypeScript),
                    "go" => push_unique(&mut detected_languages, ProjectLanguage::Go),
                    "java" => push_unique(&mut detected_languages, ProjectLanguage::Java),
                    _ => {}
                }

                match file_name {
                    "Cargo.toml" => {
                        push_unique(&mut build_systems, BuildSystemKind::Cargo);
                        push_unique(&mut detected_languages, ProjectLanguage::Rust);
                        Self::extract_cargo_manifest(path, &mut manifest_dependencies);
                    }
                    "CMakeLists.txt" => {
                        push_unique(&mut build_systems, BuildSystemKind::CMake);
                        push_unique(&mut detected_languages, ProjectLanguage::Cpp);
                    }
                    "Makefile" | "makefile" => {
                        push_unique(&mut build_systems, BuildSystemKind::Makefile);
                    }
                    "package.json" => {
                        push_unique(&mut build_systems, BuildSystemKind::Npm);
                        push_unique(&mut detected_languages, ProjectLanguage::JavaScript);
                        Self::extract_npm_manifest(path, &mut manifest_dependencies);
                    }
                    "requirements.txt" | "pyproject.toml" => {
                        push_unique(&mut build_systems, BuildSystemKind::PythonPip);
                        push_unique(&mut detected_languages, ProjectLanguage::Python);
                        Self::extract_pip_manifest(path, &mut manifest_dependencies);
                    }
                    _ => {}
                }

                // Hash relative path, byte length, and full content digest into root hash
                let rel_path = path
                    .strip_prefix(&canonical_root)
                    .unwrap_or(path)
                    .to_string_lossy();
                let rel_bytes = rel_path.as_bytes();
                let file_digest = file_hasher.finalize();
                repo_hasher.update(&(rel_bytes.len() as u64).to_le_bytes());
                repo_hasher.update(rel_bytes);
                repo_hasher.update(&actual_size.to_le_bytes());
                repo_hasher.update(file_digest.as_bytes());
            }
        }

        let primary_language = detected_languages.first().copied().unwrap_or(ProjectLanguage::Unknown);
        let root_hash_blake3 = repo_hasher.finalize().to_hex().to_string();
        let detected_frameworks = Self::detect_frameworks(&manifest_dependencies);
        let git_head_commit = Self::read_git_head_safely(&canonical_root)?;

        Ok(ProjectInspection {
            primary_language,
            detected_languages,
            build_systems,
            total_source_files: total_files,
            total_size_bytes: total_size,
            manifest_dependencies,
            root_hash_blake3,
            detected_frameworks,
            git_head_commit,
        })
    }

    fn detect_frameworks(deps: &BTreeMap<String, String>) -> Vec<String> {
        let mut out = Vec::new();
        let known = [
            ("actix-web", "ActixWeb"),
            ("axum", "Axum"),
            ("rocket", "Rocket"),
            ("tokio", "Tokio"),
            ("flask", "Flask"),
            ("django", "Django"),
            ("fastapi", "FastAPI"),
            ("express", "Express"),
            ("next", "NextJS"),
        ];
        for (pkg, label) in known {
            if deps.keys().any(|k| k.eq_ignore_ascii_case(pkg)) {
                push_unique(&mut out, label.to_string());
            }
        }
        out
    }

    /// Reads `.git/HEAD` (and ref target if symbolic) strictly as plain files inside `canonical_root`
    /// without invoking `git` subprocesses.
    fn read_git_head_safely(canonical_root: &Path) -> Result<Option<String>> {
        let git_dir = canonical_root.join(".git");
        let head_path = git_dir.join("HEAD");
        if !head_path.exists() {
            return Ok(None);
        }
        let head_canon = head_path.canonicalize().map_err(ProoflineError::Io)?;
        if !head_canon.starts_with(canonical_root) {
            return Err(ProoflineError::IsolationViolation(
                ".git/HEAD escapes repository root".to_string(),
            ));
        }
        let head_str = fs::read_to_string(&head_canon)
            .map_err(ProoflineError::Io)?
            .trim()
            .to_string();

        if let Some(ref_rel) = head_str.strip_prefix("ref: ") {
            let ref_clean = ref_rel.trim();
            if ref_clean.is_empty()
                || ref_clean.starts_with('/')
                || ref_clean.contains("..")
                || ref_clean.contains('\0')
            {
                return Err(ProoflineError::IsolationViolation(format!(
                    "Unsafe symbolic git ref in .git/HEAD: {:?}",
                    ref_clean
                )));
            }
            let ref_path = git_dir.join(ref_clean);
            if !ref_path.exists() {
                return Ok(None);
            }
            let ref_canon = ref_path.canonicalize().map_err(ProoflineError::Io)?;
            if !ref_canon.starts_with(canonical_root) {
                return Err(ProoflineError::IsolationViolation(
                    "Git ref target escapes repository root".to_string(),
                ));
            }
            let sha = fs::read_to_string(&ref_canon)
                .map_err(ProoflineError::Io)?
                .trim()
                .to_string();
            return Ok(Some(sha));
        }

        if head_str.len() == 40 && head_str.chars().all(|c| c.is_ascii_hexdigit()) {
            Ok(Some(head_str))
        } else {
            Ok(None)
        }
    }

    fn validate_symlink_target(symlink_path: &Path, canonical_root: &Path) -> Result<()> {
        let target = fs::read_link(symlink_path).map_err(|e| {
            ProoflineError::IsolationViolation(format!(
                "Unreadable symlink detected at {:?}: {}",
                symlink_path, e
            ))
        })?;

        let resolved = if target.is_absolute() {
            target
        } else {
            symlink_path.parent().unwrap_or(canonical_root).join(target)
        };

        // Check canonical target if it exists
        if let Ok(canonical_target) = resolved.canonicalize() {
            if !canonical_target.starts_with(canonical_root) {
                return Err(ProoflineError::IsolationViolation(format!(
                    "Symlink traversal detected: {:?} -> {:?}",
                    symlink_path, canonical_target
                )));
            }
            return Ok(());
        }

        // Dangling symlink: lexically normalize and verify deepest existing ancestor stays inside root
        let normalized = normalize_lexical(&resolved).ok_or_else(|| {
            ProoflineError::IsolationViolation(format!(
                "Symlink traversal escapes root lexically: {:?}",
                symlink_path
            ))
        })?;

        if !normalized.starts_with(canonical_root) {
            return Err(ProoflineError::IsolationViolation(format!(
                "Dangling symlink traversal detected: {:?} -> {:?}",
                symlink_path, normalized
            )));
        }

        let mut ancestor = normalized.as_path();
        while let Some(parent) = ancestor.parent() {
            if parent.exists() {
                let canonical_parent = parent.canonicalize().map_err(|e| {
                    ProoflineError::IsolationViolation(format!(
                        "Failed to canonicalize symlink ancestor {:?}: {}",
                        parent, e
                    ))
                })?;
                if !canonical_parent.starts_with(canonical_root) {
                    return Err(ProoflineError::IsolationViolation(format!(
                        "Symlink ancestor traversal detected: {:?} -> {:?}",
                        symlink_path, canonical_parent
                    )));
                }
                return Ok(());
            }
            ancestor = parent;
        }

        Err(ProoflineError::IsolationViolation(format!(
            "Symlink target outside repository boundary: {:?}",
            symlink_path
        )))
    }

    fn extract_cargo_manifest(path: &Path, deps: &mut BTreeMap<String, String>) {
        if let Ok(content) = fs::read_to_string(path) {
            let mut in_deps = false;
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }
                if trimmed.starts_with('[') {
                    in_deps = trimmed.starts_with("[dependencies") || trimmed.starts_with("[workspace.dependencies");
                    continue;
                }
                if in_deps && trimmed.contains('=') {
                    let mut parts = trimmed.splitn(2, '=');
                    if let (Some(k), Some(v)) = (parts.next(), parts.next()) {
                        let key = k.trim();
                        if !key.is_empty() && !key.starts_with('#') {
                            deps.insert(key.to_string(), v.trim().trim_matches('"').to_string());
                        }
                    }
                }
            }
        }
    }

    fn extract_npm_manifest(path: &Path, deps: &mut BTreeMap<String, String>) {
        if let Ok(content) = fs::read_to_string(path) {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
                if let Some(obj) = json.get("dependencies").and_then(|d| d.as_object()) {
                    for (k, v) in obj {
                        deps.insert(k.clone(), v.as_str().unwrap_or("").to_string());
                    }
                }
            }
        }
    }

    fn extract_pip_manifest(path: &Path, deps: &mut BTreeMap<String, String>) {
        if let Ok(content) = fs::read_to_string(path) {
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }
                if let Some((k, v)) = trimmed.split_once("==") {
                    deps.insert(k.trim().to_string(), v.trim().to_string());
                } else {
                    deps.insert(trimmed.to_string(), "latest".to_string());
                }
            }
        }
    }
}

fn normalize_lexical(path: &Path) -> Option<PathBuf> {
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::Prefix(p) => out.push(p.as_os_str()),
            Component::RootDir => out.push(Component::RootDir.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    return None;
                }
            }
            Component::Normal(s) => out.push(s),
        }
    }
    Some(out)
}

fn push_unique<T: PartialEq>(vec: &mut Vec<T>, item: T) {
    if !vec.contains(&item) {
        vec.push(item);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn test_safe_cargo_ingestion() {
        let dir = tempdir().unwrap();
        let cargo_toml = dir.path().join("Cargo.toml");
        let mut file = File::create(cargo_toml).unwrap();
        writeln!(file, "[package]\nname = \"test-app\"\nversion = \"0.1.0\"\n[dependencies]\nserde = \"1.0\"").unwrap();

        let src_dir = dir.path().join("src");
        fs::create_dir(&src_dir).unwrap();
        let main_rs = src_dir.join("main.rs");
        let mut main_file = File::create(main_rs).unwrap();
        writeln!(main_file, "fn main() {{ println!(\"Hello\"); }}").unwrap();

        let engine = IngestionEngine::default();
        let inspection = engine.inspect_repository(dir.path()).unwrap();

        assert_eq!(inspection.primary_language, ProjectLanguage::Rust);
        assert!(inspection.build_systems.contains(&BuildSystemKind::Cargo));
        assert_eq!(inspection.total_source_files, 2);
        assert!(inspection.manifest_dependencies.contains_key("serde"));
    }

    #[test]
    fn test_framework_detection_and_safe_git_head_read() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("requirements.txt"),
            "flask==3.0.0\nrequests==2.32.0\n",
        )
        .unwrap();
        let git_refs = dir.path().join(".git/refs/heads");
        fs::create_dir_all(&git_refs).unwrap();
        fs::write(dir.path().join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
        let sha = "a1b2c3d4e5f67890123456789012345678901234";
        fs::write(git_refs.join("main"), format!("{}\n", sha)).unwrap();

        let inspection = IngestionEngine::default().inspect_repository(dir.path()).unwrap();
        assert!(inspection.detected_frameworks.contains(&"Flask".to_string()));
        assert_eq!(inspection.git_head_commit.as_deref(), Some(sha));
    }

    #[test]
    fn test_rejects_symlink_traversal() {
        let dir = tempdir().unwrap();
        let secret_file = dir.path().join("external_secret.txt");
        File::create(&secret_file).unwrap();

        let repo_subdir = dir.path().join("repo");
        fs::create_dir(&repo_subdir).unwrap();

        #[cfg(unix)]
        {
            let malicious_link = repo_subdir.join("escape_link");
            std::os::unix::fs::symlink(&secret_file, malicious_link).unwrap();

            let engine = IngestionEngine::default();
            let result = engine.inspect_repository(&repo_subdir);
            assert!(result.is_err());
            match result {
                Err(ProoflineError::IsolationViolation(msg)) => {
                    assert!(msg.contains("Symlink traversal"));
                }
                other => panic!("Expected IsolationViolation, got: {:?}", other),
            }
        }
    }
}
