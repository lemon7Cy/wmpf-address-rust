use std::path::Path;

use crate::macho::Arch;

#[derive(Debug, Clone)]
pub struct Evidence {
    pub key: String,
    pub value: u64,
    pub confidence: &'static str,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct SceneHookCandidate {
    pub hook: u64,
    pub arg: u32,
    pub strategy: &'static str,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub version: String,
    pub load_start: u64,
    pub load_start2: u64,
    pub cdp: u64,
    pub resource: u64,
    pub load_arg: u32,
    pub scene_offset: u32,
    pub struct_offset: u32,
    pub strategy: &'static str,
    pub scene_candidates: Vec<SceneHookCandidate>,
    pub evidence: Vec<Evidence>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrategyChoice {
    Auto,
    LaunchX2,
    PreloadX3,
}

pub const SCENE_OFFSET: u32 = 456;
pub const STRUCT_OFFSET: u32 = 168;

pub fn json_config(cfg: &Config, arch: Arch) -> String {
    let arch_key = match arch {
        Arch::Arm64 => "arm64",
        Arch::X86_64 => "x86_64",
    };
    format!(
        r#"{{
  "Version": {version},
  "Arch": {{
    "{arch_key}": {{
      "LoadStartHookOffset": "0x{load_start:X}",
      "LoadStartHookOffset2": "0x{load_start2:X}",
      "CDPFilterHookOffset": "0x{cdp:X}",
      "ResourceCachePolicyHookOffset": "0x{resource:X}",
      "StructOffset": {struct_offset},
      "LoadStartHookMode": "disabled",
      "LoadStartHookArgIndex": {load_arg},
      "LoadStartHook2Mode": "runtime-scene",
      "SceneOffset": {scene_offset}
    }}
  }}
}}
"#,
        version = cfg.version,
        load_start = cfg.load_start,
        load_start2 = cfg.load_start2,
        cdp = cfg.cdp,
        resource = cfg.resource,
        struct_offset = cfg.struct_offset,
        load_arg = cfg.load_arg,
        scene_offset = cfg.scene_offset
    )
}

pub fn report(cfg: &Config, input: &Path, arch: Arch) -> String {
    let arch_str = match arch {
        Arch::Arm64 => "arm64",
        Arch::X86_64 => "x86_64",
    };
    let mut s = String::new();
    s.push_str(&format!("# WMPF Offset Finder Report {}\n\n", cfg.version));
    s.push_str(&format!("- Input: `{}`\n", input.display()));
    s.push_str(&format!("- Arch: `{arch_str}`\n"));
    s.push_str(&format!("- Strategy: `{}`\n\n", cfg.strategy));
    s.push_str("## Config\n\n```json\n");
    s.push_str(&json_config(cfg, arch));
    s.push_str("```\n\n## Evidence\n\n");
    for ev in &cfg.evidence {
        s.push_str(&format!(
            "- `{}` = `0x{:X}` ({})\n",
            ev.key, ev.value, ev.confidence
        ));
        for note in &ev.notes {
            s.push_str(&format!("  - {}\n", note));
        }
    }
    s.push_str("\n## Scene Candidates\n\n");
    for candidate in &cfg.scene_candidates {
        s.push_str(&format!(
            "- `0x{:X}` arg=`{}` strategy=`{}`\n",
            candidate.hook, candidate.arg, candidate.strategy
        ));
        for note in &candidate.notes {
            s.push_str(&format!("  - {}\n", note));
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_config() -> Config {
        Config {
            version: "19778".to_string(),
            load_start: 0x4F58B4C,
            load_start2: 0x4F65910,
            cdp: 0x842C030,
            resource: 0x4FEBA90,
            load_arg: 2,
            scene_offset: SCENE_OFFSET,
            struct_offset: STRUCT_OFFSET,
            strategy: "launch-applet-x2-config",
            scene_candidates: vec![SceneHookCandidate {
                hook: 0x4F65910,
                arg: 2,
                strategy: "launch-applet-x2-config",
                notes: vec!["test note".to_string()],
            }],
            evidence: vec![Evidence {
                key: "CDPFilterHookOffset".to_string(),
                value: 0x842C030,
                confidence: "high",
                notes: vec!["test".to_string()],
            }],
        }
    }

    #[test]
    fn test_json_config_contains_all_fields() {
        let cfg = make_test_config();
        let json = json_config(&cfg, Arch::Arm64);
        assert!(json.contains("\"Version\": 19778"));
        assert!(json.contains("0x4F58B4C"));
        assert!(json.contains("0x4F65910"));
        assert!(json.contains("0x842C030"));
        assert!(json.contains("0x4FEBA90"));
        assert!(json.contains("\"StructOffset\": 168"));
        assert!(json.contains("\"SceneOffset\": 456"));
        assert!(json.contains("\"LoadStartHookArgIndex\": 2"));
        assert!(json.contains("\"LoadStartHookMode\": \"disabled\""));
        assert!(json.contains("\"LoadStartHook2Mode\": \"runtime-scene\""));
    }

    #[test]
    fn test_json_config_arm64_key() {
        let cfg = make_test_config();
        let json = json_config(&cfg, Arch::Arm64);
        assert!(json.contains("\"arm64\""));
        assert!(!json.contains("\"x86_64\""));
    }

    #[test]
    fn test_json_config_x86_64_key() {
        let cfg = make_test_config();
        let json = json_config(&cfg, Arch::X86_64);
        assert!(json.contains("\"x86_64\""));
        assert!(!json.contains("\"arm64\""));
    }

    #[test]
    fn test_json_config_is_valid_json() {
        let cfg = make_test_config();
        let json = json_config(&cfg, Arch::Arm64);
        // Basic structural check - starts with { and ends with }
        let trimmed = json.trim();
        assert!(trimmed.starts_with('{'));
        assert!(trimmed.ends_with('}'));
    }

    #[test]
    fn test_report_contains_sections() {
        let cfg = make_test_config();
        let path = Path::new("/test/WeChatAppEx Framework");
        let r = report(&cfg, path, Arch::Arm64);
        assert!(r.contains("# WMPF Offset Finder Report 19778"));
        assert!(r.contains("## Config"));
        assert!(r.contains("## Evidence"));
        assert!(r.contains("## Scene Candidates"));
        assert!(r.contains("`CDPFilterHookOffset`"));
        assert!(r.contains("test note"));
    }

    #[test]
    fn test_report_arch_field() {
        let cfg = make_test_config();
        let path = Path::new("/test/binary");
        let r = report(&cfg, path, Arch::X86_64);
        assert!(r.contains("Arch: `x86_64`"));
    }

    #[test]
    fn test_json_config_hex_formatting() {
        let cfg = make_test_config();
        let json = json_config(&cfg, Arch::Arm64);
        // Hex values should be uppercase with 0x prefix
        assert!(json.contains("0x4F58B4C"));
        assert!(!json.contains("0x4f58b4c"));
    }
}
