//! Hardened pure-Rust USTAR `.tar` archive packager and extractor.
//! Rejects symlinks, hardlinks, device nodes, absolute paths, `..` traversal,
//! duplicate archive paths, and archive bombs.

use proofline_core::{ProoflineError, Result};
use std::collections::{BTreeMap, HashSet};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;

const BLOCK_SIZE: usize = 512;
const MAX_ENTRY_SIZE: usize = 64 * 1024 * 1024;
const MAX_TOTAL_ARCHIVE_SIZE: usize = 256 * 1024 * 1024;
const MAX_ARCHIVE_ENTRIES: usize = 4096;

/// Validates a relative archive entry path strictly.
pub fn validate_archive_rel_path(rel_path: &str) -> Result<()> {
    if rel_path.is_empty()
        || rel_path.starts_with('/')
        || rel_path.contains('\\')
        || rel_path.contains('\0')
    {
        return Err(ProoflineError::IsolationViolation(format!(
            "Unsafe archive entry path rejected: {:?}",
            rel_path
        )));
    }
    for segment in rel_path.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(ProoflineError::IsolationViolation(format!(
                "Invalid path segment in archive entry: {:?}",
                rel_path
            )));
        }
    }
    Ok(())
}

/// Writes a deterministic USTAR `.tar` file from a sorted map of `rel_path -> bytes`.
pub fn write_deterministic_tar(
    entries: &BTreeMap<String, Vec<u8>>,
    dest_tar: &Path,
) -> Result<()> {
    if entries.len() > MAX_ARCHIVE_ENTRIES {
        return Err(ProoflineError::ResourceExhausted(format!(
            "Too many archive entries ({} > {})",
            entries.len(),
            MAX_ARCHIVE_ENTRIES
        )));
    }

    let mut file = File::create(dest_tar).map_err(ProoflineError::Io)?;
    let mut total_size = 0usize;

    for (rel_path, data) in entries {
        validate_archive_rel_path(rel_path)?;
        if data.len() > MAX_ENTRY_SIZE {
            return Err(ProoflineError::ResourceExhausted(format!(
                "Archive entry {} exceeds {} bytes",
                rel_path, MAX_ENTRY_SIZE
            )));
        }
        total_size = total_size.saturating_add(data.len());
        if total_size > MAX_TOTAL_ARCHIVE_SIZE {
            return Err(ProoflineError::ResourceExhausted(
                "Archive exceeds total size limit".to_string(),
            ));
        }

        let header = build_ustar_header(rel_path, data.len() as u64)?;
        file.write_all(&header).map_err(ProoflineError::Io)?;
        file.write_all(data).map_err(ProoflineError::Io)?;

        let rem = data.len() % BLOCK_SIZE;
        if rem != 0 {
            let pad = vec![0u8; BLOCK_SIZE - rem];
            file.write_all(&pad).map_err(ProoflineError::Io)?;
        }
    }

    // Two 512-byte zero blocks mark EOF
    let eof = [0u8; BLOCK_SIZE * 2];
    file.write_all(&eof).map_err(ProoflineError::Io)?;
    file.flush().map_err(ProoflineError::Io)?;
    Ok(())
}

/// Reads and strictly validates a USTAR `.tar` archive into memory.
pub fn read_deterministic_tar(tar_path: &Path) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut file = File::open(tar_path).map_err(ProoflineError::Io)?;
    let meta = file.metadata().map_err(ProoflineError::Io)?;
    if !meta.is_file() {
        return Err(ProoflineError::IsolationViolation(
            "Bundle archive is not a regular file".to_string(),
        ));
    }
    if meta.len() as usize > MAX_TOTAL_ARCHIVE_SIZE + BLOCK_SIZE * MAX_ARCHIVE_ENTRIES {
        return Err(ProoflineError::ResourceExhausted(
            "Archive file size exceeds safe bound".to_string(),
        ));
    }

    let mut out = BTreeMap::new();
    let mut seen_paths = HashSet::new();
    let mut total_extracted = 0usize;
    let mut header = [0u8; BLOCK_SIZE];

    loop {
        match file.read_exact(&mut header) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Err(ProoflineError::ParseFailure(
                    "Truncated tar archive before EOF blocks".to_string(),
                ));
            }
            Err(e) => return Err(ProoflineError::Io(e)),
        }

        if header.iter().all(|&b| b == 0) {
            break;
        }

        verify_ustar_checksum(&header)?;
        let typeflag = header[156];
        let name = extract_cstr(&header[0..100])?;
        let prefix = extract_cstr(&header[345..500])?;
        let full_path = if prefix.is_empty() {
            name
        } else {
            format!("{}/{}", prefix, name)
        };

        // Allow directories (b'5') with zero payload, and regular files (b'0' or b'\0').
        // Reject symlinks (b'2'), hardlinks (b'1'), devices, FIFOs, and extended headers.
        match typeflag {
            b'0' | b'\0' => {}
            b'5' => {
                let clean = full_path.trim_end_matches('/');
                if !clean.is_empty() {
                    validate_archive_rel_path(clean)?;
                }
                continue;
            }
            other => {
                return Err(ProoflineError::IsolationViolation(format!(
                    "Disallowed tar entry type '{}' for {:?}",
                    other as char, full_path
                )));
            }
        }

        validate_archive_rel_path(&full_path)?;
        if !seen_paths.insert(full_path.clone()) {
            return Err(ProoflineError::IsolationViolation(format!(
                "Duplicate archive entry rejected: {}",
                full_path
            )));
        }
        if out.len() >= MAX_ARCHIVE_ENTRIES {
            return Err(ProoflineError::ResourceExhausted(
                "Archive entry count exceeds limit".to_string(),
            ));
        }

        let size = parse_octal(&header[124..136])?;
        if size > MAX_ENTRY_SIZE {
            return Err(ProoflineError::ResourceExhausted(format!(
                "Archive entry {} exceeds size limit ({} bytes)",
                full_path, size
            )));
        }
        total_extracted = total_extracted.saturating_add(size);
        if total_extracted > MAX_TOTAL_ARCHIVE_SIZE {
            return Err(ProoflineError::ResourceExhausted(
                "Decompressed archive total size exceeds limit".to_string(),
            ));
        }

        let mut data = vec![0u8; size];
        file.read_exact(&mut data).map_err(|e| {
            ProoflineError::ParseFailure(format!("Failed reading tar payload for {}: {}", full_path, e))
        })?;

        let rem = size % BLOCK_SIZE;
        if rem != 0 {
            let mut pad = vec![0u8; BLOCK_SIZE - rem];
            file.read_exact(&mut pad).map_err(|e| {
                ProoflineError::ParseFailure(format!("Truncated tar padding for {}: {}", full_path, e))
            })?;
        }

        out.insert(full_path, data);
    }

    Ok(out)
}

/// Safely materializes validated tar entries into `dest_dir` for isolated inspection/replay.
pub fn extract_entries_safely(entries: &BTreeMap<String, Vec<u8>>, dest_dir: &Path) -> Result<()> {
    fs::create_dir_all(dest_dir).map_err(ProoflineError::Io)?;
    let canonical_dest = dest_dir.canonicalize().map_err(ProoflineError::Io)?;

    for (rel_path, bytes) in entries {
        validate_archive_rel_path(rel_path)?;
        let target = canonical_dest.join(rel_path);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(ProoflineError::Io)?;
            let canonical_parent = parent.canonicalize().map_err(ProoflineError::Io)?;
            if !canonical_parent.starts_with(&canonical_dest) {
                return Err(ProoflineError::IsolationViolation(format!(
                    "Extracted path escapes destination directory: {:?}",
                    target
                )));
            }
        }
        fs::write(&target, bytes).map_err(ProoflineError::Io)?;
    }

    Ok(())
}

fn build_ustar_header(rel_path: &str, size: u64) -> Result<[u8; BLOCK_SIZE]> {
    let mut header = [0u8; BLOCK_SIZE];
    let (prefix, name) = split_ustar_path(rel_path)?;

    header[..name.len()].copy_from_slice(name.as_bytes());
    if !prefix.is_empty() {
        header[345..345 + prefix.len()].copy_from_slice(prefix.as_bytes());
    }

    let mode = if rel_path.ends_with(".sh") {
        b"0000755\0"
    } else {
        b"0000644\0"
    };
    header[100..108].copy_from_slice(mode);
    header[108..116].copy_from_slice(b"0000000\0"); // uid 0
    header[116..124].copy_from_slice(b"0000000\0"); // gid 0

    let size_oct = format!("{:011o}\0", size);
    if size_oct.len() != 12 {
        return Err(ProoflineError::ResourceExhausted(
            "File too large for USTAR octal size field".to_string(),
        ));
    }
    header[124..136].copy_from_slice(size_oct.as_bytes());
    header[136..148].copy_from_slice(b"00000000000\0"); // deterministic mtime 0
    header[148..156].copy_from_slice(b"        "); // checksum placeholder
    header[156] = b'0'; // regular file
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");

    let sum: u32 = header.iter().map(|&b| b as u32).sum();
    let chksum = format!("{:06o}\0 ", sum);
    header[148..156].copy_from_slice(chksum.as_bytes());

    Ok(header)
}

fn split_ustar_path(rel_path: &str) -> Result<(&str, &str)> {
    if rel_path.len() <= 100 {
        return Ok(("", rel_path));
    }
    if let Some(pos) = rel_path.rfind('/') {
        let prefix = &rel_path[..pos];
        let name = &rel_path[pos + 1..];
        if prefix.len() <= 155 && name.len() <= 100 && !name.is_empty() {
            return Ok((prefix, name));
        }
    }
    Err(ProoflineError::ParseFailure(format!(
        "Archive entry path too long for USTAR format: {}",
        rel_path
    )))
}

fn verify_ustar_checksum(header: &[u8; BLOCK_SIZE]) -> Result<()> {
    let expected = parse_octal(&header[148..156])? as u32;
    let mut sum = 0u32;
    for (idx, &b) in header.iter().enumerate() {
        if (148..156).contains(&idx) {
            sum += b' ' as u32;
        } else {
            sum += b as u32;
        }
    }
    if sum != expected {
        return Err(ProoflineError::ParseFailure(format!(
            "Invalid USTAR header checksum: expected {:o}, got {:o}",
            expected, sum
        )));
    }
    Ok(())
}

fn parse_octal(field: &[u8]) -> Result<usize> {
    let s = std::str::from_utf8(field)
        .map_err(|_| ProoflineError::ParseFailure("Non-UTF8 octal header field".to_string()))?
        .trim_matches(|c: char| c == '\0' || c == ' ');
    if s.is_empty() {
        return Ok(0);
    }
    usize::from_str_radix(s, 8).map_err(|_| {
        ProoflineError::ParseFailure(format!("Invalid octal value in tar header: {:?}", s))
    })
}

fn extract_cstr(field: &[u8]) -> Result<String> {
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    std::str::from_utf8(&field[..end])
        .map(|s| s.to_string())
        .map_err(|_| ProoflineError::ParseFailure("Non-UTF8 tar path header".to_string()))
}
