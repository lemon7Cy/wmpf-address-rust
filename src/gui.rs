use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Instant;

use eframe::egui;

use crate::config::StrategyChoice;
use crate::macho::Arch;

/// 检测文件格式
enum FileFormat {
    MachO,
    Pe,
}

fn detect_format(data: &[u8]) -> FileFormat {
    if data.len() >= 2 && data[0] == 0x4D && data[1] == 0x5A {
        FileFormat::Pe
    } else {
        FileFormat::MachO
    }
}

/// GUI 应用状态
pub struct App {
    // 输入状态
    file_path: String,
    arch: Arch,
    strategy: StrategyChoice,
    version: String,

    // 输出状态
    logs: Vec<String>,
    last_config: String,
    scanning: bool,

    // MCP 状态
    mcp_running: bool,
    mcp_port: String,
    mcp_status: String,

    // 通道
    log_rx: mpsc::Receiver<String>,
    log_tx: mpsc::Sender<String>,

    // 结果通道
    result_rx: mpsc::Receiver<ResultMsg>,
    result_tx: mpsc::Sender<ResultMsg>,
}

enum ResultMsg {
    Config(String),
    Error(String),
    Done,
}

impl Default for App {
    fn default() -> Self {
        let (log_tx, log_rx) = mpsc::channel();
        let (result_tx, result_rx) = mpsc::channel();
        Self {
            file_path: String::new(),
            arch: Arch::X86_64,
            strategy: StrategyChoice::Auto,
            version: String::new(),
            logs: Vec::new(),
            last_config: String::new(),
            scanning: false,
            mcp_running: false,
            mcp_port: "13778".to_string(),
            mcp_status: "未启动".to_string(),
            log_rx,
            log_tx,
            result_rx,
            result_tx,
        }
    }
}

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        configure_chinese_font(&cc.egui_ctx);
        Self::default()
    }

    fn start_scan(&mut self) {
        if self.scanning {
            return;
        }
        if self.file_path.is_empty() {
            self.logs.push("[错误] 请先选择文件".to_string());
            return;
        }

        let path = PathBuf::from(&self.file_path);
        if !path.exists() {
            self.logs
                .push(format!("[错误] 文件不存在: {}", self.file_path));
            return;
        }

        self.scanning = true;
        self.last_config.clear();

        let arch = self.arch;
        let strategy = self.strategy;
        let version = if self.version.is_empty() {
            None
        } else {
            Some(self.version.clone())
        };
        let log_tx = self.log_tx.clone();
        let result_tx = self.result_tx.clone();

        std::thread::spawn(move || {
            run_scan(path, arch, strategy, version, log_tx, result_tx);
        });
    }

    fn copy_json_to_clipboard(&self) {
        if self.last_config.is_empty() {
            return;
        }
        match arboard::Clipboard::new() {
            Ok(mut clipboard) => {
                if let Err(e) = clipboard.set_text(self.last_config.clone()) {
                    eprintln!("复制到剪贴板失败: {e}");
                }
            }
            Err(e) => {
                eprintln!("初始化剪贴板失败: {e}");
            }
        }
    }

    fn handle_dropped_files(&mut self, ctx: &egui::Context) {
        let dropped = ctx.input(|i| i.raw.dropped_files.clone());
        if let Some(file) = dropped.first() {
            if let Some(path) = &file.path {
                self.file_path = path.to_string_lossy().to_string();
                if let Ok(data) = std::fs::read(path) {
                    match detect_format(&data) {
                        FileFormat::Pe => {
                            self.arch = Arch::X86_64;
                            self.logs
                                .push(format!("[检测] PE 文件: {}", self.file_path));
                        }
                        FileFormat::MachO => {
                            self.logs
                                .push(format!("[检测] Mach-O 文件: {}", self.file_path));
                        }
                    }
                }
            }
        }
    }

    fn poll_channels(&mut self) {
        while let Ok(msg) = self.log_rx.try_recv() {
            self.logs.push(msg);
        }
        while let Ok(msg) = self.result_rx.try_recv() {
            match msg {
                ResultMsg::Config(json) => {
                    self.last_config = json;
                }
                ResultMsg::Error(e) => {
                    self.logs.push(format!("[失败] {e}"));
                    self.scanning = false;
                }
                ResultMsg::Done => {
                    self.scanning = false;
                }
            }
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_channels();
        self.handle_dropped_files(ctx);

        // ── 顶部标题栏 ──
        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("WMPF Offset Finder");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(
                        egui::RichText::new(format!("v{}", env!("CARGO_PKG_VERSION")))
                            .small()
                            .weak(),
                    );
                });
            });
        });

        // ── 底部状态栏 ──
        egui::TopBottomPanel::bottom("bottom_panel").show(ctx, |ui| {
            ui.horizontal(|ui| {
                let status_color = if self.mcp_running {
                    egui::Color32::from_rgb(0, 180, 0)
                } else {
                    egui::Color32::GRAY
                };
                ui.colored_label(status_color, format!("MCP: {}", self.mcp_status));
                ui.separator();
                ui.label(format!("日志: {} 条", self.logs.len()));
            });
        });

        // ── 主面板 ──
        egui::CentralPanel::default().show(ctx, |ui| {
            // 文件选择
            ui.group(|ui| {
                ui.label(egui::RichText::new("文件").strong());
                ui.horizontal(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.file_path)
                            .hint_text("拖拽文件到此处，或点击浏览...")
                            .desired_width(ui.available_width() - 80.0),
                    );
                    if ui.button("浏览...").clicked() {
                        if let Some(path) = rfd::FileDialog::new()
                            .add_filter("二进制文件", &["dll", "dylib", "so", "exe", "bin"])
                            .add_filter("所有文件", &["*"])
                            .pick_file()
                        {
                            self.file_path = path.to_string_lossy().to_string();
                            if let Ok(data) = std::fs::read(&path) {
                                match detect_format(&data) {
                                    FileFormat::Pe => {
                                        self.arch = Arch::X86_64;
                                        self.logs.push(format!(
                                            "[检测] PE 文件: {}",
                                            self.file_path
                                        ));
                                    }
                                    FileFormat::MachO => {
                                        self.logs.push(format!(
                                            "[检测] Mach-O 文件: {}",
                                            self.file_path
                                        ));
                                    }
                                }
                            }
                        }
                    }
                });

                if self.file_path.is_empty() {
                    ui.add_space(4.0);
                    let rect = ui.available_rect_before_wrap();
                    ui.painter().rect_stroke(
                        rect,
                        4.0,
                        egui::Stroke::new(1.0, egui::Color32::from_gray(100)),
                        egui::StrokeKind::Outside,
                    );
                    ui.put(
                        rect,
                        egui::Label::new(
                            egui::RichText::new("将 DLL 或二进制文件拖拽到此处")
                                .weak()
                                .italics(),
                        ),
                    );
                }
            });

            ui.add_space(6.0);

            // 扫描参数
            ui.group(|ui| {
                ui.label(egui::RichText::new("扫描参数").strong());
                ui.horizontal(|ui| {
                    ui.label("架构:");
                    egui::ComboBox::from_id_salt("arch_select")
                        .selected_text(format!("{:?}", self.arch))
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut self.arch, Arch::Arm64, "Arm64");
                            ui.selectable_value(&mut self.arch, Arch::X86_64, "X86_64");
                        });
                    ui.add_space(16.0);
                    ui.label("策略:");
                    egui::ComboBox::from_id_salt("strategy_select")
                        .selected_text(match self.strategy {
                            StrategyChoice::Auto => "auto",
                            StrategyChoice::LaunchX2 => "launch-x2",
                            StrategyChoice::PreloadX3 => "preload-x3",
                        })
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut self.strategy, StrategyChoice::Auto, "auto");
                            ui.selectable_value(
                                &mut self.strategy,
                                StrategyChoice::LaunchX2,
                                "launch-x2",
                            );
                            ui.selectable_value(
                                &mut self.strategy,
                                StrategyChoice::PreloadX3,
                                "preload-x3",
                            );
                        });
                    ui.add_space(16.0);
                    ui.label("版本:");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.version)
                            .hint_text("自动检测")
                            .desired_width(100.0),
                    );
                });
            });

            ui.add_space(6.0);

            // 操作按钮
            ui.horizontal(|ui| {
                let scan_btn = ui.add_enabled(
                    !self.scanning && !self.file_path.is_empty(),
                    egui::Button::new(if self.scanning { "扫描中..." } else { "开始扫描" }),
                );
                if scan_btn.clicked() {
                    self.start_scan();
                }

                let copy_btn = ui.add_enabled(
                    !self.last_config.is_empty(),
                    egui::Button::new("复制 JSON"),
                );
                if copy_btn.clicked() {
                    self.copy_json_to_clipboard();
                    self.logs.push("[操作] JSON 配置已复制到剪贴板".to_string());
                }

                ui.add_space(16.0);

                if self.mcp_running {
                    if ui.button("停止 MCP").clicked() {
                        self.mcp_running = false;
                        self.mcp_status = "已停止".to_string();
                        self.logs.push("[MCP] 服务器已停止".to_string());
                    }
                } else {
                    if ui.button("启动 MCP").clicked() {
                        self.mcp_running = true;
                        if self.mcp_port.is_empty() {
                            self.mcp_port = "13778".to_string();
                        }
                        self.mcp_status = format!("运行中 @ 127.0.0.1:{}", self.mcp_port);
                        self.logs.push(format!(
                            "[MCP] 服务器启动在 127.0.0.1:{}",
                            self.mcp_port
                        ));
                    }
                }

                ui.add_space(4.0);
                ui.label("端口:");
                ui.add(egui::TextEdit::singleline(&mut self.mcp_port).desired_width(60.0));
            });

            ui.add_space(6.0);

            // ── 下方区域：左侧扫描结果 + 右侧日志 ──
            let remaining = ui.available_height();
            ui.columns(2, |cols| {
                // 左列：扫描结果
                egui::Frame::group(cols[0].style())
                    .show(&mut cols[0], |ui| {
                        ui.label(egui::RichText::new("扫描结果").strong());
                        egui::ScrollArea::vertical()
                            .auto_shrink([false, false])
                            .max_height(remaining - 48.0)
                            .show(ui, |ui| {
                                if self.last_config.is_empty() {
                                    ui.label(
                                        egui::RichText::new("等待扫描...").weak().italics(),
                                    );
                                } else {
                                    ui.add(
                                        egui::TextEdit::multiline(&mut self.last_config.as_str())
                                            .font(egui::TextStyle::Monospace)
                                            .desired_width(ui.available_width()),
                                    );
                                }
                            });
                    });

                // 右列：日志
                egui::Frame::group(cols[1].style())
                    .show(&mut cols[1], |ui| {
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new("日志").strong());
                            if ui.small_button("清空").clicked() {
                                self.logs.clear();
                            }
                        });
                        egui::ScrollArea::vertical()
                            .auto_shrink([false, false])
                            .stick_to_bottom(true)
                            .max_height(remaining - 48.0)
                            .show(ui, |ui| {
                                for log in &self.logs {
                                    ui.monospace(log);
                                }
                                if self.logs.is_empty() {
                                    ui.label(
                                        egui::RichText::new("等待操作...").weak().italics(),
                                    );
                                }
                            });
                    });
            });
        });

        if self.scanning {
            ctx.request_repaint();
        }
    }
}

fn run_scan(
    path: PathBuf,
    arch: Arch,
    strategy: StrategyChoice,
    version: Option<String>,
    log_tx: mpsc::Sender<String>,
    result_tx: mpsc::Sender<ResultMsg>,
) {
    let send_log = |msg: String| {
        let _ = log_tx.send(msg);
    };

    let total_start = Instant::now();

    // ── 读取文件 ──
    send_log(format!("读取文件: {}", path.display()));
    let load_start = Instant::now();

    let data = match std::fs::read(&path) {
        Ok(d) => d,
        Err(e) => {
            let _ = result_tx.send(ResultMsg::Error(format!("读取文件失败: {e}")));
            return;
        }
    };

    let load_elapsed = load_start.elapsed();
    send_log(format!(
        "文件加载完成: 0x{:X} bytes ({:.2?})",
        data.len(),
        load_elapsed
    ));

    // ── 格式检测 ──
    let format = detect_format(&data);

    // ── 扫描分析 ──
    let scan_start = Instant::now();

    let cfg = match format {
        FileFormat::Pe => {
            send_log("格式: PE (Windows DLL)".to_string());
            let pe = match crate::pe::parse_pe(&data) {
                Ok(p) => p,
                Err(e) => {
                    let _ = result_tx.send(ResultMsg::Error(format!("PE 解析失败: {e}")));
                    return;
                }
            };
            send_log(format!(
                "PE: arch={:?}, image_base=0x{:X}, sections={}",
                pe.arch,
                pe.image_base,
                pe.sections.len()
            ));
            match crate::analysis::analyze_pe(&pe, arch, version, strategy, false) {
                Ok(cfg) => cfg,
                Err(e) => {
                    let _ = result_tx.send(ResultMsg::Error(format!("PE 分析失败: {e}")));
                    return;
                }
            }
        }
        FileFormat::MachO => {
            send_log("格式: Mach-O (macOS)".to_string());
            let slice = match crate::macho::parse_slice(&data, arch) {
                Ok(s) => s,
                Err(e) => {
                    let _ = result_tx.send(ResultMsg::Error(format!("Mach-O 解析失败: {e}")));
                    return;
                }
            };
            send_log(format!(
                "Mach-O: arch={:?}, sections={}",
                arch,
                slice.sections.len()
            ));
            match crate::analysis::analyze(&slice, arch, version, strategy, false) {
                Ok(cfg) => cfg,
                Err(e) => {
                    let _ = result_tx.send(ResultMsg::Error(format!("分析失败: {e}")));
                    return;
                }
            }
        }
    };

    let scan_elapsed = scan_start.elapsed();

    // ── 输出结果 ──
    send_log("────────── 扫描结果 ──────────".to_string());
    send_log(format!("版本: {}", cfg.version));
    send_log(format!("LoadStartHookOffset:  0x{:X}", cfg.load_start));
    send_log(format!("LoadStartHookOffset2: 0x{:X}", cfg.load_start2));
    send_log(format!("CDPFilterHookOffset:  0x{:X}", cfg.cdp));
    send_log(format!("ResourceCachePolicy:  0x{:X}", cfg.resource));
    send_log(format!("策略: {}", cfg.strategy));
    send_log(format!("场景候选: {} 个", cfg.scene_candidates.len()));

    for (i, c) in cfg.scene_candidates.iter().enumerate() {
        send_log(format!(
            "  候选{}: 0x{:X} arg={} strategy={}",
            i, c.hook, c.arg, c.strategy
        ));
    }

    send_log("────────── 置信度 ──────────".to_string());
    for ev in &cfg.evidence {
        send_log(format!("{}: 0x{:X} ({})", ev.key, ev.value, ev.confidence));
    }

    let total_elapsed = total_start.elapsed();
    send_log("────────── 耗时统计 ──────────".to_string());
    send_log(format!("文件加载: {:.2?}", load_elapsed));
    send_log(format!("扫描分析: {:.2?}", scan_elapsed));
    send_log(format!("总耗时:   {:.2?}", total_elapsed));

    // 生成 JSON
    let json = crate::config::json_config(&cfg, arch);
    let _ = result_tx.send(ResultMsg::Config(json));
    let _ = result_tx.send(ResultMsg::Done);
}

/// 配置中文字体支持
fn configure_chinese_font(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();

    if let Some(data) = load_system_chinese_font() {
        fonts
            .font_data
            .insert("chinese".to_owned(), egui::FontData::from_owned(data).into());

        if let Some(proportional) = fonts.families.get_mut(&egui::FontFamily::Proportional) {
            proportional.insert(0, "chinese".to_owned());
        }
        if let Some(monospace) = fonts.families.get_mut(&egui::FontFamily::Monospace) {
            monospace.push("chinese".to_owned());
        }

        ctx.set_fonts(fonts);
    }
}

fn load_system_chinese_font() -> Option<Vec<u8>> {
    #[cfg(target_os = "windows")]
    {
        let font_paths = [
            r"C:\Windows\Fonts\msyh.ttc",
            r"C:\Windows\Fonts\msyhbd.ttc",
            r"C:\Windows\Fonts\simhei.ttf",
            r"C:\Windows\Fonts\simsun.ttc",
        ];
        for path in &font_paths {
            if let Ok(data) = std::fs::read(path) {
                return Some(data);
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        let font_paths = [
            "/System/Library/Fonts/PingFang.ttc",
            "/System/Library/Fonts/STHeiti Medium.ttc",
            "/Library/Fonts/Arial Unicode.ttf",
        ];
        for path in &font_paths {
            if let Ok(data) = std::fs::read(path) {
                return Some(data);
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        let font_paths = [
            "/usr/share/fonts/truetype/wqy/wqy-microhei.ttc",
            "/usr/share/fonts/truetype/noto/NotoSansCJK-Regular.ttc",
        ];
        for path in &font_paths {
            if let Ok(data) = std::fs::read(path) {
                return Some(data);
            }
        }
    }

    eprintln!("警告: 未找到系统中文字体");
    None
}
