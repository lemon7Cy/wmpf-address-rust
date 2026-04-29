mod analysis;
mod arm64;
mod config;
mod macho;

use std::env;
use std::fs;
use std::path::PathBuf;

use config::StrategyChoice;

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args = parse_args()?;
    let data = fs::read(&args.input)
        .map_err(|e| format!("failed to read {}: {e}", args.input.display()))?;
    let slice = macho::parse_slice(&data)?;
    let cfg = analysis::analyze(&slice, args.version, args.strategy, args.verbose)?;
    let json = config::json_config(&cfg);
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
        fs::write(&report_path, config::report(&cfg, &args.input))
            .map_err(|e| format!("failed to write {}: {e}", report_path.display()))?;
        eprintln!("wrote {}", config_path.display());
        eprintln!("wrote {}", report_path.display());
    }

    Ok(())
}

#[derive(Debug)]
struct Args {
    input: PathBuf,
    version: Option<String>,
    out_dir: Option<PathBuf>,
    strategy: StrategyChoice,
    print_only: bool,
    verbose: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut iter = env::args().skip(1);
    let mut input = None;
    let mut version = None;
    let mut out_dir = None;
    let mut strategy = StrategyChoice::Auto;
    let mut print_only = false;
    let mut verbose = false;
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--arch" => {
                let arch = iter.next().ok_or("--arch requires a value")?;
                if arch != "arm64" {
                    return Err("only --arch arm64 is supported in this version".to_string());
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
        input: input.ok_or_else(usage)?,
        version,
        out_dir,
        strategy,
        print_only,
        verbose,
    })
}

fn usage() -> String {
    "usage: wmpf-offset-finder <WeChatAppEx Framework> --arch arm64 [--version 19778] [--strategy auto|launch-x2|preload-x3] [--out-dir /path/to/WMPFDebugger-GUI] [--print] [--verbose]".to_string()
}
