//! Reading an app/plugin bundle and deriving the identifiers used for matching
//! (`-[ACBundle initWithURL:]`, `-normalizeBundleId`).

use crate::text::{self, is_blank, normalized};
use anyhow::{bail, Context, Result};
use plist::{Dictionary, Value};
use regex::Regex;
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Extensions treated as plugin bundles (`+[ACBundle allowedPluginExtensions]`).
pub const PLUGIN_EXTENSIONS: &[&str] = &[
    "framework", "plugin", "webplugin", "bundle", "appex", "mdimporter", "dext", "qlgenerator", "xpc",
    "driver", "prefpane", "mailbundle", "component", "service",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum BundleKind {
    App,
    Plugin,
}

#[derive(Debug, Clone, Serialize)]
pub struct Bundle {
    /// Resolved location of the bundle.
    pub path: PathBuf,
    /// The symlink the user pointed at, if any (removed along with the bundle).
    pub alias: Option<PathBuf>,
    pub kind: BundleKind,
    pub name: String,
    pub display_name: Option<String>,
    pub executable: String,
    /// Normalized bundle identifier.
    pub id: Option<String>,
    /// Identifier exactly as written in Info.plist.
    pub raw_id: Option<String>,
    pub version: String,
    /// Keys of `SMPrivilegedExecutables`.
    pub privileged_executables: Vec<String>,
    /// True for helpers nested inside another bundle: they only match by bundle id.
    pub is_sub: bool,
}

impl Bundle {
    pub fn open(path: &Path) -> Result<Self> {
        let meta = std::fs::symlink_metadata(path).with_context(|| format!("cannot read {}", path.display()))?;
        let (path, alias) = if meta.file_type().is_symlink() {
            (std::fs::canonicalize(path)?, Some(path.to_path_buf()))
        } else {
            (path.to_path_buf(), None)
        };
        let file_name = path.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
        let ext = text::extension(&file_name).map(str::to_lowercase);
        let kind = match ext.as_deref() {
            Some("app") => BundleKind::App,
            Some("dylib") => bail!("not supported: {}", path.display()),
            Some(e) if PLUGIN_EXTENSIONS.contains(&e) => BundleKind::Plugin,
            _ => bail!("not a supported bundle: {}", path.display()),
        };
        let info = read_info_plist(&path);
        let get = |k: &str| info.as_ref().and_then(|d| d.get(k)).and_then(Value::as_string).map(str::to_string);

        let executable = get("CFBundleExecutable").unwrap_or_else(|| file_name.clone());
        let name = derive_name(get("CFBundleName").as_deref(), &file_name);
        let display_name = get("CFBundleDisplayName")
            .map(|d| normalized(&d))
            .filter(|d| !d.is_empty() && !text::eq_ci(d, &name));
        let raw_id = get("CFBundleIdentifier").filter(|s| !is_blank(s));
        let id = raw_id.as_deref().map(normalize_bundle_id);
        let version = get("CFBundleShortVersionString")
            .filter(|s| !is_blank(s))
            .or_else(|| get("CFBundleVersion").filter(|s| !is_blank(s)))
            .unwrap_or_default();
        let privileged_executables = info
            .as_ref()
            .and_then(|d| d.get("SMPrivilegedExecutables"))
            .and_then(Value::as_dictionary)
            .map(|d| d.keys().cloned().collect())
            .unwrap_or_default();

        Ok(Bundle { path, alias, kind, name, display_name, executable, id, raw_id, version, privileged_executables, is_sub: false })
    }

    pub fn file_name(&self) -> String {
        self.path.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default()
    }

    /// Bundle id or "" (Foundation treats a nil id as length 0).
    pub fn id_str(&self) -> &str {
        self.id.as_deref().unwrap_or("")
    }
}

/// Info.plist location differs by bundle type.
pub fn read_info_plist(bundle: &Path) -> Option<Dictionary> {
    ["Contents/Info.plist", "Resources/Info.plist", "Info.plist"]
        .iter()
        .find_map(|rel| plist::Value::from_file(bundle.join(rel)).ok())
        .and_then(Value::into_dictionary)
}

/// CFBundleName → normalized; fall back to the file name; drop a trailing ` 12.34.56` date suffix.
fn derive_name(cf_name: Option<&str>, file_name: &str) -> String {
    static DATE: OnceLock<Regex> = OnceLock::new();
    let mut name = cf_name.map(normalized).unwrap_or_default();
    if is_blank(&name) {
        name = normalized(text::stem(file_name));
    }
    let re = DATE.get_or_init(|| Regex::new(r"(?i)^.+( \d{2}.\d{2}.\d{2})$").unwrap());
    if let Some(start) = re.captures(&name).and_then(|c| c.get(1)).map(|m| m.start()) {
        name.truncate(start);
    }
    name
}

/// `-[ACBundle normalizeBundleId]`: strip `.app`, `.demo`, `.trial`, version digits … from the end.
pub fn normalize_bundle_id(id: &str) -> String {
    static RE: OnceLock<Regex> = OnceLock::new();
    if text::ns_len(id) <= 7 {
        return id.to_string();
    }
    let re = RE.get_or_init(|| Regex::new(r"(?i)\.(app|application|demo|trial)?[0-9\-_ab]*$").unwrap());
    match re.find(id) {
        Some(m) if m.start() > 4 && !m.is_empty() => id[..m.start()].to_string(),
        _ => id.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundle_id_normalization() {
        assert_eq!(normalize_bundle_id("com.foo.bar.app"), "com.foo.bar");
        assert_eq!(normalize_bundle_id("com.foo.Bar2"), "com.foo.Bar2"); // needs a dot before the digits
        assert_eq!(normalize_bundle_id("com.foo.bar.app2"), "com.foo.bar");
        assert_eq!(normalize_bundle_id("com.foo.bar.10"), "com.foo.bar");
        assert_eq!(normalize_bundle_id("com.foo.bar.trial"), "com.foo.bar");
        assert_eq!(normalize_bundle_id("com.foo.bar"), "com.foo.bar");
        assert_eq!(normalize_bundle_id("com.a.b"), "com.a.b"); // too short
        // Quirk kept for parity: a final component made only of [ab0-9-_] is removed.
        assert_eq!(normalize_bundle_id("com.foo.ab"), "com.foo");
    }

    #[test]
    fn name_drops_date_suffix() {
        assert_eq!(derive_name(Some("Tool 24.01.05"), "x.app"), "Tool");
        assert_eq!(derive_name(None, "My App.app"), "My App");
        assert_eq!(derive_name(Some("  "), ".Hidden..app"), "Hidden");
    }
}
