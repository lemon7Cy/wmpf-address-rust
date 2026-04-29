use std::env;
use std::fs;
use std::path::PathBuf;

use wmpf_offset_finder::config::StrategyChoice;
use wmpf_offset_finder::macho::Arch;

#[derive(Debug)]
enum Mode {
    Analyze,
    Serve { binary: Option<PathBuf>, arch: Arch },
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args = parse_args()?;
    match args.mode {
        Mode::Serve { binary, arch } => run_serve(binary, arch),
        Mode::Analyze => run_analyze(args),
    }
}

fn run_analyze(args: Args) -> Result<(), String> {
    let input = args.input.ok_or_else(usage)?;
    let data = fs::read(&input)
        .map_err(|e| format!("failed to read {}: {e}", input.display()))?;
    let slice = wmpf_offset_finder::macho::parse_slice(&data, args.arch)?;
    let cfg = wmpf_offset_finder::analysis::analyze(
        &slice,
        args.arch,
        args.version,
        args.strategy,
        args.verbose,
    )?;
    let json = wmpf_offset_finder::config::json_config(&cfg, args.arch);
    println!("{json}");

    if args.print_only {
        return Ok(());
    }

    if let Some(out_dir) = args.out_dir {
        let config_dir = out_dir.join("frida/config");
        let docs_dir = out_dir.join("docs");
        fs::create_dir_all(&config_dir)
            .map_err(|e| format!("failed to create {}: {e}", config_dir.display()))?;
        fs::create_dir_all(&docs_dir)
            .map_err(|e| format!("failed to create {}: {e}", docs_dir.display()))?;
        let config_path = config_dir.join(format!("addresses.{}.json", cfg.version));
        let report_path = docs_dir.join(format!("offsets-{}-auto.md", cfg.version));
        fs::write(&config_path, &json)
            .map_err(|e| format!("failed to write {}: {e}", config_path.display()))?;
        fs::write(&report_path, wmpf_offset_finder::config::report(&cfg, &input, args.arch))
            .map_err(|e| format!("failed to write {}: {e}", report_path.display()))?;
        eprintln!("wrote {}", config_path.display());
        eprintln!("wrote {}", report_path.display());
    }

    Ok(())
}

fn run_serve(binary: Option<PathBuf>, arch: Arch) -> Result<(), String> {
    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| format!("failed to create tokio runtime: {e}"))?;
    rt.block_on(async {
        wmpf_offset_finder::mcp::run_server(binary, arch).await
    })
}

#[derive(Debug)]
struct Args {
    mode: Mode,
    input: Option<PathBuf>,
    arch: Arch,
    version: Option<String>,
    out_dir: Option<PathBuf>,
    strategy: StrategyChoice,
    print_only: bool,
    verbose: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut iter = env::args().skip(1);
    let mut mode = Mode::Analyze;
    let mut input = None;
    let mut arch = Arch::Arm64;
    let mut version = None;
    let mut out_dir = None;
    let mut strategy = StrategyChoice::Auto;
    let mut print_only = false;
    let mut verbose = false;

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "serve" => {
                mode = Mode::Serve {
                    binary: None,
                    arch: Arch::Arm64,
                };
            }
            "--binary" => {
                let path = iter.next().ok_or("--binary requires a value")?;
                match &mut mode {
                    Mode::Serve { binary, .. } => *binary = Some(PathBuf::from(path)),
                    _ => return Err("--binary is only valid with 'serve' subcommand".to_string()),
                }
            }
            "--arch" => {
                let value = iter.next().ok_or("--arch requires a value")?;
                let a = match value.as_str() {
                    "arm64" => Arch::Arm64,
                    "x86_64" | "x64" => Arch::X86_64,
                    _ => return Err(format!("unsupported arch: {value}\n\n{}", usage())),
                };
                match &mut mode {
                    Mode::Serve { arch, .. } => *arch = a,
                    _ => arch = a,
                }
            }
            "--version" => version = Some(iter.next().ok_or("--version requires a value")?),
            "--strategy" => {
                let value = iter.next().ok_or("--strategy requires a value")?;
                strategy = match value.as_str() {
                    "auto" => StrategyChoice::Auto,
                    "launch-x2" => StrategyChoice::LaunchX2,
                    "preload-x3" => StrategyChoice::PreloadX3,
                    _ => return Err(format!("unsupported strategy: {value}\n\n{}", usage())),
                };
            }
            "--out-dir" => {
                out_dir = Some(PathBuf::from(
                    iter.next().ok_or("--out-dir requires a value")?,
                ))
            }
            "--print" => print_only = true,
            "--verbose" | "-v" => verbose = true,
            "-h" | "--help" => return Err(usage()),
            other if other.starts_with('-') => {
                return Err(format!("unknown option: {other}\n\n{}", usage()));
            }
            other => {
                if input.is_some() {
                    return Err(format!("unexpected extra argument: {other}"));
                }
                input = Some(PathBuf::from(other));
            }
        }
    }
    Ok(Args {
        mode,
        input,
        arch,
        version,
        out_dir,
        strategy,
        print_only,
        verbose,
    })
}

fn usage() -> String {
    concat!(
        "usage:\n",
        "  wmpf-offset-finder <binary> [--arch arm64|x86_64] [--version N] [--strategy auto|launch-x2|preload-x3] [--out-dir DIR] [--print] [--verbose]\n",
        "  wmpf-offset-finder serve [--binary <path>] [--arch arm64|x86_64]"
    ).to_string()
}
