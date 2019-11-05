extern crate structopt;
extern crate env_logger;

use tabox::{SandboxImplementation, Sandbox, SandboxConfigurationBuilder};
use std::path::PathBuf;
use serde::{Serialize, Deserialize};
use structopt::StructOpt;

/// Command line arguments of the program
#[derive(Debug, Clone, Serialize, Deserialize, StructOpt)]
#[structopt(
    name = "tabox",
    about = "Execute code in a secure sandbox",
)]
struct Args {
    /// Time limit for the execution
    #[structopt(long, short)]
    time_limit: Option<u64>,

    /// Memory limit fot the execution
    #[structopt(long, short)]
    memory_limit: Option<u64>,

    /// Absolute path of the executable
    executable: PathBuf,

    /// Arguments to pass to the executable
    args: Vec<String>,

    /// Allowed paths inside the sandbox
    #[structopt(long = "allow", short = "a")]
    allowed_paths: Vec<PathBuf>,

    /// Deny these system calls in the sandbox
    #[structopt(long)]
    syscall_filter: Option<Vec<String>>,

    /// Redirect stdin from this file
    #[structopt(long, short = "i")]
    stdin: Option<PathBuf>,

    /// Redirect stdout from this file
    #[structopt(long, short = "o")]
    stdout: Option<PathBuf>,

    /// Redirect stderr from this file
    #[structopt(long, short = "e")]
    stderr: Option<PathBuf>,

    /// Allow insecure sandbox
    #[structopt(long)]
    allow_insecure: bool,

    /// output in JSON format
    #[structopt(long, short)]
    json: bool,
}

fn main() {
    env_logger::init();

    let args = Args::from_args();

    if !SandboxImplementation::is_secure() && !args.allow_insecure {
        eprintln!("Your platform doesn't support a secure sandbox!");
        eprintln!("Run with --allow-insecure if you really want to execute it anyway");
        return;
    }

    let config = SandboxConfigurationBuilder::default()
        .time_limit(args.time_limit)
        .memory_limit(args.memory_limit)
        .syscall_filter(args.syscall_filter)
        .stdout(args.stdout)
        .stdin(args.stdin)
        .stderr(args.stderr)
        .executable(args.executable)
        .env(vec![])
        .args(args.args)
        .mount_paths(args.allowed_paths)
        .build()
        .unwrap();

    let sandbox = SandboxImplementation::run(config)
        .expect("Error creating sandbox");
    let result = sandbox.wait()
        .expect("Error waiting for sandbox result");

    if args.json {
        println!("{}", serde_json::to_string(&result).unwrap());
    } else {
        println!("{:#?}", result);
    }
}
