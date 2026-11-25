use proofline_sandbox::guest_agent;
use proofline_sandbox::DEFAULT_VSOCK_PORT;
use std::env;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

struct StdioStream {
    stdin: io::Stdin,
    stdout: io::Stdout,
}

impl Read for StdioStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stdin.read(buf)
    }
}

impl Write for StdioStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stdout.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.stdout.flush()
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!(
            "proofline-guest-agent [--stdio | --unix-sock <path> [--once] | --vsock-port <port>]"
        );
        return ExitCode::SUCCESS;
    }

    if args.iter().any(|a| a == "--stdio") {
        let mut stream = StdioStream {
            stdin: io::stdin(),
            stdout: io::stdout(),
        };
        return match guest_agent::serve_vsock_stream(&mut stream) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("proofline-guest-agent stdio error: {}", e);
                ExitCode::from(1)
            }
        };
    }

    #[cfg(unix)]
    if let Some(pos) = args.iter().position(|a| a == "--unix-sock") {
        if let Some(path) = args.get(pos + 1) {
            let one_shot = args.iter().any(|a| a == "--once");
            return match guest_agent::serve_unix_socket(&PathBuf::from(path), one_shot) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("proofline-guest-agent unix-sock error: {}", e);
                    ExitCode::from(1)
                }
            };
        }
    }

    #[cfg(target_os = "linux")]
    {
        let port = args
            .iter()
            .position(|a| a == "--vsock-port")
            .and_then(|pos| args.get(pos + 1))
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(DEFAULT_VSOCK_PORT);
        let skip_airgap = args.iter().any(|a| a == "--no-airgap-check");
        match guest_agent::serve_af_vsock(port, !skip_airgap) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("proofline-guest-agent vsock error: {}", e);
                ExitCode::from(1)
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("proofline-guest-agent requires Linux AF_VSOCK or --stdio / --unix-sock");
        ExitCode::from(1)
    }
}
