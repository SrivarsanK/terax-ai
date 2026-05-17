use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum WorkspaceEnv {
    #[default]
    Local,
    Wsl {
        distro: String,
    },
}

impl WorkspaceEnv {
    pub fn from_option(workspace: Option<Self>) -> Self {
        workspace.unwrap_or_default()
    }

    pub fn is_wsl(&self) -> bool {
        matches!(self, Self::Wsl { .. })
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct WslDistro {
    pub name: String,
    pub default: bool,
    pub running: bool,
}

#[cfg(windows)]
pub fn resolve_path(path: &str, workspace: &WorkspaceEnv) -> PathBuf {
    match workspace {
        WorkspaceEnv::Local => PathBuf::from(path),
        WorkspaceEnv::Wsl { distro } => wsl_path_to_unc(distro, path),
    }
}

#[cfg(not(windows))]
pub fn resolve_path(path: &str, _workspace: &WorkspaceEnv) -> PathBuf {
    PathBuf::from(path)
}

/// True for WSL distro names safe to splice into a UNC path. Real WSL distros
/// are alphanumeric with `.`, `_`, `-` separators (e.g. `Ubuntu-22.04`). Reject
/// anything that could traverse out of the `\\wsl.localhost\<distro>\` prefix
/// (`..`, `\`, `/`, `:`, `?`, `*`, control bytes) or empty names.
#[cfg(windows)]
fn is_safe_distro_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 255 {
        return false;
    }
    if name == "." || name == ".." || name.starts_with('.') {
        return false;
    }
    name.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ' '))
        && !name.contains("..")
}

#[cfg(windows)]
pub fn wsl_path_to_unc(distro: &str, path: &str) -> PathBuf {
    // Defense-in-depth: refuse to construct a UNC path with a distro name that
    // could escape the WSL share root via `..`, `\`, or other path metachars.
    // Returns a clearly-invalid path that downstream `is_dir()`/`metadata()`
    // checks will reject. The webview's distro list comes from `wsl.exe --list`
    // and is normally trustworthy, but a locally-registered malicious distro
    // can name itself with traversal characters; this filter blocks that.
    if !is_safe_distro_name(distro) {
        return PathBuf::from(r"\\wsl.localhost\__terax_invalid_distro__");
    }
    let normalized = path.replace('\\', "/");
    let trimmed = normalized.trim_start_matches('/');
    let primary = PathBuf::from(format!(
        r"\\wsl.localhost\{}\{}",
        distro,
        trimmed.replace('/', r"\")
    ));
    if primary.exists() {
        return primary;
    }
    PathBuf::from(format!(r"\\wsl$\{}\{}", distro, trimmed.replace('/', r"\")))
}

#[cfg(windows)]
pub fn decode_command_output(bytes: &[u8]) -> String {
    if bytes.starts_with(&[0xff, 0xfe]) || looks_utf16le(bytes) {
        let start = if bytes.starts_with(&[0xff, 0xfe]) {
            2
        } else {
            0
        };
        let units: Vec<u16> = bytes[start..]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&units)
    } else {
        String::from_utf8_lossy(bytes).into_owned()
    }
}

#[cfg(windows)]
fn looks_utf16le(bytes: &[u8]) -> bool {
    if bytes.len() < 4 || !bytes.len().is_multiple_of(2) {
        return false;
    }
    let nul_odd = bytes.iter().skip(1).step_by(2).filter(|b| **b == 0).count();
    nul_odd * 2 >= bytes.len() / 2
}

#[cfg(windows)]
fn run_wsl(args: &[&str]) -> Result<String, String> {
    let out = std::process::Command::new("wsl.exe")
        .args(args)
        .output()
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        let stderr = decode_command_output(&out.stderr);
        return Err(stderr.trim().to_string());
    }
    Ok(decode_command_output(&out.stdout))
}

#[cfg(windows)]
fn list_distros_blocking() -> Result<Vec<WslDistro>, String> {
    let out = run_wsl(&["--list", "--verbose"])?;
    let mut distros = Vec::new();
    for raw in out.lines().skip(1) {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let default = line.starts_with('*');
        let line = line.trim_start_matches('*').trim();
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
            continue;
        }
        let state_idx = parts.len() - 2;
        let name = parts[..state_idx].join(" ");
        let state = parts[state_idx];
        distros.push(WslDistro {
            name,
            default,
            running: state.eq_ignore_ascii_case("Running"),
        });
    }
    Ok(distros)
}

#[tauri::command]
pub async fn wsl_list_distros() -> Result<Vec<WslDistro>, String> {
    #[cfg(not(windows))]
    {
        Ok(Vec::new())
    }
    #[cfg(windows)]
    {
        tauri::async_runtime::spawn_blocking(list_distros_blocking)
            .await
            .map_err(|e| e.to_string())?
    }
}

#[tauri::command]
pub async fn wsl_default_distro() -> Result<Option<String>, String> {
    #[cfg(not(windows))]
    {
        Ok(None)
    }
    #[cfg(windows)]
    {
        tauri::async_runtime::spawn_blocking(|| {
            let distros = list_distros_blocking()?;
            Ok(distros
                .iter()
                .find(|d| d.default)
                .map(|d| d.name.clone())
                .or_else(|| distros.first().map(|d| d.name.clone())))
        })
        .await
        .map_err(|e| e.to_string())?
    }
}

#[tauri::command]
pub fn wsl_home(distro: String) -> Result<String, String> {
    #[cfg(not(windows))]
    {
        let _ = distro;
        Err("WSL is only available on Windows".into())
    }
    #[cfg(windows)]
    {
        let out = run_wsl(&["-d", &distro, "--exec", "sh", "-lc", "printf %s \"$HOME\""])?;
        let home = out.trim().to_string();
        if home.is_empty() {
            Err(format!("could not resolve WSL home for {distro}"))
        } else {
            Ok(home)
        }
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn distro_validator_accepts_real_names() {
        assert!(is_safe_distro_name("Ubuntu"));
        assert!(is_safe_distro_name("Ubuntu-22.04"));
        assert!(is_safe_distro_name("Debian"));
        assert!(is_safe_distro_name("Alpine_3.18"));
        assert!(is_safe_distro_name("openSUSE-Tumbleweed"));
    }

    #[test]
    fn distro_validator_rejects_path_traversal() {
        assert!(!is_safe_distro_name(".."));
        assert!(!is_safe_distro_name("..\\..\\Windows"));
        assert!(!is_safe_distro_name("../foo"));
        assert!(!is_safe_distro_name("foo/bar"));
        assert!(!is_safe_distro_name("foo\\bar"));
        assert!(!is_safe_distro_name("foo..bar"));
    }

    #[test]
    fn distro_validator_rejects_special_chars() {
        assert!(!is_safe_distro_name("foo:bar"));
        assert!(!is_safe_distro_name("foo?bar"));
        assert!(!is_safe_distro_name("foo*bar"));
        assert!(!is_safe_distro_name("foo\0bar"));
        assert!(!is_safe_distro_name(""));
        assert!(!is_safe_distro_name(".hidden"));
    }

    #[test]
    fn wsl_path_to_unc_blocks_traversal_distro() {
        // Malicious distro name must produce a path that is_dir() will reject,
        // never escape the WSL share root.
        let p = wsl_path_to_unc("..\\..\\..\\Windows", "/etc/passwd");
        let s = p.to_string_lossy();
        assert!(s.contains("__terax_invalid_distro__"), "got: {s}");
        assert!(!s.contains("\\..\\"), "got: {s}");
    }

    #[test]
    fn wsl_path_to_unc_accepts_valid_distro() {
        let p = wsl_path_to_unc("Ubuntu", "/etc/hosts");
        let s = p.to_string_lossy();
        assert!(!s.contains("__terax_invalid_distro__"), "got: {s}");
    }
}
