use std::env;
use std::fs;
use std::path::PathBuf;

use eframe::egui;
use wmpf_offset_finder::config::StrategyChoice;
use wmpf_offset_finder::macho::Arch;

/// Detect file format based on magic bytes
enum FileFormat {
    MachO,
    Pe,
}

fn detect_format(data: &[u8]) -> FileFormat {
    // Check for MZ header (PE file)
    if data.len() >= 2 && data[0] == 0x4D && data[1] == 0x5A {
        return FileFormat::Pe;
    }
    // Default to Mach-O
    FileFormat::MachO
}

#[derive(Debug)]
enum Mode {
    Analyze,
    Serve { binary: Option<PathBuf>, arch: Arch },
    Gui,
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
        Mode::Gui => run_gui(),
    }
}

fn run_analyze(args: Args) -> Result<(), String> {
    let input = args.input.ok_or_else(usage)?;
    let data = fs::read(&input)
        .map_err(|e| format!("failed to read {}: {e}", input.display()))?;

    let format = detect_format(&data);
    let cfg = match format {
        FileFormat::MachO => {
            let slice = wmpf_offset_finder::macho::parse_slice(&data, args.arch)?;
            wmpf_offset_finder::analysis::analyze(
                &slice,
                args.arch,
                args.version,
                args.strategy,
                args.verbose,
            )?
        }
        FileFormat::Pe => {
            let pe = wmpf_offset_finder::pe::parse_pe(&data)?;
            let arch = match pe.arch {
                wmpf_offset_finder::pe::Arch::X86_64 => Arch::X86_64,
                wmpf_offset_finder::pe::Arch::X86 => Arch::X86_64, // Treat x86 as x86_64 for now
            };
            wmpf_offset_finder::analysis::analyze_pe(
                &pe,
                arch,
                args.version,
                args.strategy,
                args.verbose,
            )?
        }
    };

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

fn run_gui() -> Result<(), String> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([800.0, 600.0])
            .with_min_inner_size([600.0, 400.0]),
        ..Default::default()
    };
    eframe::run_native(
        "WMPF Offset Finder",
        options,
        Box::new(|cc| Ok(Box::new(wmpf_offset_finder::gui::App::new(cc)))),
    )
    .map_err(|e| format!("GUI 启动失败: {e}"))
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
            "gui" => {
                mode = Mode::Gui;
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
        "  wmpf-offset-finder serve [--binary <path>] [--arch arm64|x86_64]\n",
        "  wmpf-offset-finder gui"
    ).to_string()
}
