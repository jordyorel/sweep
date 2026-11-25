//! Finding the files an app leaves behind (`-[ACAppBundle fetchRelatedFiles]`).
//!
//! The section numbers in comments refer to `docs/appcleaner-internals.md`.
//! Every finding records *why* it matched, so a dry run can be audited.

use crate::bundle::{Bundle, BundleKind};
use crate::env::Env;
use crate::text::{self, contains_ci, eq_ci, has_iprefix, normalized, ns_len, remove_spaces, strip_trailing_digits};
use regex::Regex;
use serde::Serialize;
use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    Bundle,
    Alias,
    ParentFolder,
    Preferences,
    ApplicationSupport,
    Caches,
    Containers,
    GroupContainers,
    ApplicationScripts,
    SavedState,
    LaunchAgents,
    LaunchDaemons,
    PrivilegedHelpers,
    Receipts,
    Logs,
    CrashReports,
    WebData,
    Services,
    Other,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub path: PathBuf,
    pub category: Category,
    /// Human-readable rule that produced the match.
    pub reason: String,
    /// Whether it should be removed unless the user unticks it.
    pub selected: bool,
    /// Allocated size on disk in bytes.
    pub size: u64,
    /// Bundle id of the nested helper that matched, if not the main bundle.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub via: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub bundle: Bundle,
    pub nested: Vec<Bundle>,
    /// System-protected (SIP / `/System/Applications`): cannot be removed.
    pub sip_protected: bool,
    pub findings: Vec<Finding>,
}

impl Report {
    pub fn total_size(&self) -> u64 {
        self.findings.iter().map(|f| f.size).sum()
    }
}

#[derive(Debug, Clone, Default)]
pub struct Options {
    /// Read App Group entitlements with `codesign` (slower; on by default in the CLI).
    pub read_entitlements: bool,
    /// Compute allocated sizes.
    pub sizes: bool,
}

type Hit = (PathBuf, String);

/// Walk `dirs` like AppCleaner's NSDirectoryEnumerator loop.
///
/// `max_depth == 0` means direct children only. A matching directory is not descended into.
/// Matching is on the normalized item name only.
fn walk(dirs: &[PathBuf], max_depth: usize, m: &dyn Fn(&str) -> Option<String>) -> Vec<Hit> {
    fn visit(dir: &Path, level: usize, max: usize, m: &dyn Fn(&str) -> Option<String>, out: &mut Vec<Hit>) {
        let Ok(rd) = fs::read_dir(dir) else { return };
        for e in rd.flatten() {
            let name = normalized(&e.file_name().to_string_lossy());
            let is_dir = e.file_type().map(|t| t.is_dir()).unwrap_or(false); // symlinks are not followed
            if let Some(reason) = m(&name) {
                out.push((e.path(), reason));
            } else if is_dir && max > 0 && level < max {
                visit(&e.path(), level + 1, max, m, out);
            }
        }
    }
    let mut out = Vec::new();
    for d in dirs {
        visit(d, 1, max_depth, m, &mut out);
    }
    out
}

/// §5: the name-based matcher used for Library roots, caches, logs …
struct NameMatcher {
    id: String,
    is_sub: bool,
    names: Vec<String>,
    patterns: Vec<Regex>,
}

impl NameMatcher {
    fn new(b: &Bundle) -> Self {
        let mut names = vec![b.name.clone(), remove_spaces(&b.name), strip_trailing_digits(&b.name)];
        if let Some(d) = &b.display_name {
            names.push(d.clone());
            names.push(remove_spaces(d));
        }
        names.retain(|n| !n.is_empty());
        let patterns = names
            .iter()
            .map(|n| Regex::new(&format!(r"(?i)^{}(?:[.\-_\s\d]+.*)?$", regex::escape(n))).unwrap())
            .collect();
        NameMatcher { id: b.id_str().to_string(), is_sub: b.is_sub, names, patterns }
    }

    fn check(&self, f: &str) -> Option<String> {
        let id = &self.id;
        if ns_len(id) >= 8 && contains_ci(f, id) {
            return Some(format!("name contains bundle id `{id}`"));
        }
        if ns_len(id) >= 4 && has_iprefix(f, id) {
            return Some(format!("name starts with bundle id `{id}`"));
        }
        if self.is_sub {
            return None;
        }
        let base = text::stem(f);
        for (n, re) in self.names.iter().zip(&self.patterns) {
            if ns_len(n) < 4 {
                if eq_ci(f, n) || eq_ci(base, n) {
                    return Some(format!("name equals app name `{n}`"));
                }
            } else if re.is_match(f) {
                return Some(format!("name matches app name `{n}`"));
            }
        }
        None
    }
}

struct Collector<'a> {
    env: &'a Env,
    out: Vec<Finding>,
    via: Option<String>,
}

impl Collector<'_> {
    fn add(&mut self, hits: Vec<Hit>, cat: Category, selected: bool) {
        for (path, reason) in hits {
            self.out.push(Finding { path, category: cat, reason, selected, size: 0, via: self.via.clone() });
        }
    }
    fn add_cat_by_parent(&mut self, hits: Vec<Hit>, fallback: Category) {
        for (path, reason) in hits {
            let cat = categorize(self.env, &path).unwrap_or(fallback);
            self.out.push(Finding { path, category: cat, reason, selected: true, size: 0, via: self.via.clone() });
        }
    }
}

/// Best category for a hit found by a broad scan (e.g. the Library root).
fn categorize(env: &Env, p: &Path) -> Option<Category> {
    let parent = p.parent()?;
    for lib in [&env.user_library, &env.local_library] {
        let Ok(rel) = parent.strip_prefix(lib) else { continue };
        let first = rel.components().next().map(|c| c.as_os_str().to_string_lossy().into_owned());
        return Some(match first.as_deref() {
            None => Category::Other,
            Some("Application Support") => Category::ApplicationSupport,
            Some("Caches") => Category::Caches,
            Some("Logs") => Category::Logs,
            Some("Services") => Category::Services,
            Some("Preferences") => Category::Preferences,
            _ => Category::Other,
        });
    }
    None
}

/// Find everything related to the app at `path`.
pub fn scan(path: &Path, env: &Env, opts: &Options) -> anyhow::Result<Report> {
    let bundle = Bundle::open(path)?;
    let sip_protected = is_sip_protected(&bundle.path);
    let mut c = Collector { env, out: Vec::new(), via: None };

    // §6.1 nested bundles + embedded Automator services
    let (nested, services) =
        if bundle.kind == BundleKind::App { parse_bundle(&bundle.path) } else { (vec![], vec![]) };

    fetch(&bundle, &services, opts, &mut c);
    for n in &nested {
        c.via = n.id.clone();
        fetch(n, &[], opts, &mut c);
    }
    c.via = None;

    // De-duplicate (first rule wins), drop protected roots and the bundle itself.
    let mut seen = HashSet::new();
    let mut findings: Vec<Finding> = c
        .out
        .into_iter()
        .filter(|f| f.path != bundle.path && !env.is_protected_root(&f.path) && seen.insert(f.path.clone()))
        .collect();
    findings.sort_by(|a, b| a.path.cmp(&b.path));

    // The bundle first, then its alias and parent folder (§6.12).
    let mut head = vec![Finding {
        path: bundle.path.clone(),
        category: Category::Bundle,
        reason: "the app bundle".into(),
        selected: !sip_protected,
        size: 0,
        via: None,
    }];
    if let Some(a) = &bundle.alias {
        head.push(Finding { path: a.clone(), category: Category::Alias, reason: "symlink to the app".into(), selected: true, size: 0, via: None });
    }
    if let Some((p, reason)) = related_parent_dir(&bundle, env) {
        findings.retain(|f| !f.path.starts_with(&p));
        // Deviation from AppCleaner: never pre-selected, because a whole folder may hold other things.
        head.push(Finding { path: p, category: Category::ParentFolder, reason, selected: false, size: 0, via: None });
    }
    head.append(&mut findings);
    let mut findings = head;

    if opts.sizes {
        for f in &mut findings {
            f.size = allocated_size(&f.path);
        }
    }
    Ok(Report { bundle, nested, sip_protected, findings })
}

/// Everything except the parent folder, for one bundle (main or nested).
fn fetch(b: &Bundle, services: &[String], opts: &Options, c: &mut Collector) {
    let env = c.env;
    let id = b.id_str().to_string();
    let idl = ns_len(&id);
    let nm = NameMatcher::new(b);
    let is_app = b.kind == BundleKind::App;

    // §6.2 services (top-level app only)
    if is_app && !b.is_sub {
        let svc: HashSet<String> = services.iter().cloned().collect();
        let hits = walk(&env.library("Services"), 0, &|f| {
            if svc.contains(&f.to_lowercase()) {
                Some("Automator service shipped inside the app".into())
            } else {
                nm.check(f)
            }
        });
        c.add(hits, Category::Services, true);
    }

    // §6.4 preferences
    let name = b.name.clone();
    let name_ns = remove_spaces(&name);
    let sourceforge = id == "net.sourceforge";
    let prefs = walk(&env.library("Preferences"), 0, &|f| {
        if is_app && has_iprefix(f, "widget-") {
            return None;
        }
        if !id.is_empty() && !(is_app && sourceforge) {
            let hit = if idl < 4 { eq_ci(f, &format!("{id}.plist")) } else { has_iprefix(f, &id) };
            if hit {
                return Some(format!("preference file for `{id}`"));
            }
        }
        if !is_app || b.is_sub {
            return None;
        }
        let nl = ns_len(&name);
        if nl >= 4 && (has_iprefix(f, &name_ns) || has_iprefix(f, &name)) {
            return Some(format!("starts with app name `{name}`"));
        }
        if nl >= 8 && (contains_ci(f, &name_ns) || contains_ci(f, &name)) {
            return Some(format!("contains app name `{name}`"));
        }
        None
    });
    c.add(prefs, Category::Preferences, true);
    if idl > 3 && !(is_app && sourceforge) {
        let mut dirs = env.library("Preferences/ByHost");
        dirs.extend(env.library("SyncedPreferences"));
        let hits = walk(&dirs, 0, &|f| has_iprefix(f, &id).then(|| format!("starts with bundle id `{id}`")));
        c.add(hits, Category::Preferences, true);
    }

    // §6.5 misc (top-level only)
    if !b.is_sub {
        let mut dirs = env.library("");
        dirs.extend(env.app_support(""));
        let is_prefpane = text::extension(&b.file_name()).is_some_and(|e| e.eq_ignore_ascii_case("prefPane"));
        if !is_prefpane {
            dirs.extend(env.library("PreferencePanes"));
        }
        dirs.extend(env.library("Services"));
        dirs.extend(env.library("Safari/Extensions"));
        dirs.push(env.users_shared.clone());
        let hits = walk(&dirs, 0, &|f| nm.check(f));
        c.add_cat_by_parent(hits, Category::Other);

        if idl >= 8 {
            let by_id = |f: &str| has_iprefix(f, &id).then(|| format!("starts with bundle id `{id}`"));
            for sub in ["Cookies", "HTTPStorages", "WebKit"] {
                c.add(walk(&env.library(sub), 0, &by_id), Category::WebData, true);
            }
            let recent = env.app_support("com.apple.sharedfilelist/com.apple.LSSharedFileList.ApplicationRecentDocuments");
            c.add(walk(&recent, 0, &by_id), Category::Other, true);
        }
    }

    // §6.6 containers + App Groups
    if !id.is_empty() {
        let mut dirs = env.library("Containers");
        dirs.extend(env.library("Application Scripts"));
        let hits = walk(&dirs, 0, &|f| eq_ci(f, &id).then(|| format!("container for `{id}`")));
        for (p, r) in hits {
            let cat = if p.parent().is_some_and(|x| x.ends_with("Containers")) { Category::Containers } else { Category::ApplicationScripts };
            c.add(vec![(p, r)], cat, true);
        }
        let groups = if opts.read_entitlements { app_groups(&b.path) } else { vec![] };
        if !groups.is_empty() {
            let hits = walk(&env.library("Application Scripts"), 0, &|f| {
                groups
                    .iter()
                    .find(|g| eq_ci(f, g) || has_iprefix(f, &format!("{g}.")))
                    .map(|g| format!("scripts for app group `{g}`"))
            });
            c.add(hits, Category::ApplicationScripts, true);
        }
        let hits = walk(&env.library("Group Containers"), 0, &|f| {
            if eq_ci(f, &id) {
                Some(format!("group container named `{id}`"))
            } else {
                groups.iter().any(|g| g == f).then(|| format!("app group `{f}` from the app's entitlements"))
            }
        });
        // Shared with sibling apps, so not pre-selected (same as AppCleaner).
        c.add(hits, Category::GroupContainers, false);
    }

    // §6.7 caches (apps)
    if is_app {
        let mut dirs = env.caches("");
        dirs.extend(env.caches("Metadata"));
        dirs.extend(env.caches("com.apple.Safari/Extensions"));
        c.add(walk(&dirs, 0, &|f| nm.check(f)), Category::Caches, true);
        if idl > 3 && !b.is_sub {
            let by_stem = |f: &str| has_iprefix(text::stem(f), &id).then(|| format!("help index for `{id}`"));
            c.add(walk(&env.caches("com.apple.helpd/Generated"), 0, &by_stem), Category::Caches, true);
            c.add(walk(&env.caches("com.apple.helpd/SDMHelpData"), 4, &by_stem), Category::Caches, true);
        }
    }

    // §6.8 saved state
    if !id.is_empty() {
        let hits = walk(&env.library("Saved Application State"), 0, &|f| {
            if has_iprefix(f, &id) {
                Some(format!("starts with bundle id `{id}`"))
            } else if ns_len(&name) >= 8 && has_iprefix(f, &name) {
                Some(format!("starts with app name `{name}`"))
            } else {
                None
            }
        });
        c.add(hits, Category::SavedState, true);
    }

    // §6.9 package receipts (apps)
    if is_app && idl >= 4 {
        let hits = walk(std::slice::from_ref(&env.receipts), 0, &|f| {
            has_iprefix(f, &id).then(|| format!("installer receipt for `{id}`"))
        });
        c.add(hits, Category::Receipts, true);
    }

    // §6.10 launch agents / daemons / privileged helpers
    let agents = env.library("LaunchAgents");
    let daemons = env.library("LaunchDaemons");
    let helpers = env.library("PrivilegedHelperTools");
    let launchd_cat = |p: &Path| {
        if p.parent().is_some_and(|x| x.ends_with("LaunchDaemons")) { Category::LaunchDaemons } else { Category::LaunchAgents }
    };
    if idl >= 8 {
        let mut dirs = agents.clone();
        dirs.extend(daemons.clone());
        for (p, r) in walk(&dirs, 0, &|f| has_iprefix(f, &id).then(|| format!("starts with bundle id `{id}`"))) {
            let cat = launchd_cat(&p);
            c.add(vec![(p, r)], cat, true);
        }
    }
    for k in &b.privileged_executables {
        let mut dirs = agents.clone();
        dirs.extend(daemons.clone());
        let plist_hits = walk(&dirs, 0, &|f| {
            (text::extension(f).is_some_and(|e| eq_ci(e, "plist")) && eq_ci(text::stem(f), k))
                .then(|| format!("job for SMPrivilegedExecutables `{k}`"))
        });
        for (p, r) in plist_hits {
            let cat = launchd_cat(&p);
            c.add(vec![(p, r)], cat, true);
        }
        let tool_hits = walk(&helpers, 0, &|f| eq_ci(f, k).then(|| format!("SMPrivilegedExecutables `{k}`")));
        c.add(tool_hits, Category::PrivilegedHelpers, true);
    }
    if idl >= 8 {
        let hits = walk(&helpers, 0, &|f| has_iprefix(f, &id).then(|| format!("starts with bundle id `{id}`")));
        c.add(hits, Category::PrivilegedHelpers, true);
    }

    // §6.11 crash reports + logs
    let exe = format!("{}_", b.executable);
    let mut crash_dirs = env.app_support("CrashReporter");
    crash_dirs.extend(env.library("Logs/DiagnosticReports"));
    let hits = walk(&crash_dirs, 0, &|f| has_iprefix(f, &exe).then(|| format!("crash report for `{}`", b.executable)));
    c.add(hits, Category::CrashReports, true);
    c.add(walk(&env.library("Logs"), 3, &|f| nm.check(f)), Category::Logs, true);
}

/// §6.1: helpers nested inside the app, and Automator `.workflow` names.
fn parse_bundle(app: &Path) -> (Vec<Bundle>, Vec<String>) {
    fn visit(dir: &Path, level: usize, nested: &mut Vec<Bundle>, services: &mut Vec<String>) {
        let Ok(rd) = fs::read_dir(dir) else { return };
        for e in rd.flatten() {
            let p = e.path();
            let name = e.file_name().to_string_lossy().into_owned();
            let is_dir = e.file_type().map(|t| t.is_dir()).unwrap_or(false);
            let ext = text::extension(&name).map(str::to_lowercase);
            match ext.as_deref() {
                Some("framework") => continue, // frameworks are never treated as helpers
                Some("workflow") => services.push(name.to_lowercase()),
                _ => {
                    if let Ok(mut b) = Bundle::open(&p) {
                        if b.id.is_some() && !b.id_str().to_lowercase().starts_with("org.sparkle-project") {
                            b.is_sub = true;
                            nested.push(b);
                        }
                    }
                }
            }
            if is_dir && level < 6 {
                visit(&p, level + 1, nested, services);
            }
        }
    }
    let (mut nested, mut services) = (vec![], vec![]);
    visit(app, 1, &mut nested, &mut services);
    (nested, services)
}

/// §6.12: an enclosing folder created for the app (e.g. `/Applications/Foo/Foo.app`).
///
/// Deviation: AppCleaner searches the unescaped regex `<name>[0-9BETAbeta.-]*` anywhere in the
/// folder name. We anchor and escape it, so `Foo` no longer sweeps up `FooBar Tools`.
fn related_parent_dir(b: &Bundle, env: &Env) -> Option<(PathBuf, String)> {
    if b.kind != BundleKind::App || b.is_sub {
        return None;
    }
    let parent = b.path.parent()?.to_path_buf();
    if env.app_dirs.contains(&parent) || parent.parent().is_none() || parent == env.users_shared {
        return None;
    }
    let pname = remove_spaces(&parent.file_name()?.to_string_lossy());
    let app = remove_spaces(text::stem(&b.file_name()));
    if !eq_ci(&pname, "Applications") {
        let hit = if ns_len(&app) < 4 {
            eq_ci(&pname, &app)
        } else {
            Regex::new(&format!(r"(?i)^{}[0-9BETAbeta.\-]*$", regex::escape(&app))).unwrap().is_match(&pname)
        };
        if hit {
            return Some((parent, format!("folder named after the app `{app}`")));
        }
    }
    if b.path.to_string_lossy().starts_with("/opt/homebrew-cask") {
        return Some((parent, "Homebrew cask folder".into()));
    }
    None
}

/// App Group identifiers from the code signature's entitlements.
pub fn app_groups(bundle: &Path) -> Vec<String> {
    let Ok(out) = Command::new("/usr/bin/codesign").args(["-d", "--entitlements", "-", "--xml"]).arg(bundle).output() else {
        return vec![];
    };
    let Ok(v) = plist::Value::from_reader_xml(&out.stdout[..]) else { return vec![] };
    match v.as_dictionary().and_then(|d| d.get("com.apple.security.application-groups")) {
        Some(plist::Value::String(s)) => vec![s.clone()],
        Some(plist::Value::Array(a)) => a.iter().filter_map(|x| x.as_string().map(str::to_string)).collect(),
        _ => vec![],
    }
}

extern "C" {
    fn csr_get_active_config(config: *mut u32) -> i32;
}

/// SIP is on unless `CSR_ALLOW_UNRESTRICTED_FS` (0x2) is set.
pub fn sip_enabled() -> bool {
    let mut cfg: u32 = 0;
    // SAFETY: csr_get_active_config writes one u32 to the pointer we pass.
    let rc = unsafe { csr_get_active_config(&mut cfg) };
    rc != 0 || cfg & 0x2 == 0
}

const SF_RESTRICTED: u32 = 0x0008_0000;

/// `-[NSURL isSystemProtected]`
pub fn is_sip_protected(p: &Path) -> bool {
    if p.to_string_lossy().starts_with("/System/Applications/") {
        return true;
    }
    sip_enabled() && fs::symlink_metadata(p).map(|m| std::os::macos::fs::MetadataExt::st_flags(&m) & SF_RESTRICTED != 0).unwrap_or(false)
}

/// Allocated bytes, recursively, without following symlinks; hard links counted once.
pub fn allocated_size(p: &Path) -> u64 {
    fn go(p: &Path, seen: &mut HashSet<(u64, u64)>) -> u64 {
        let Ok(m) = fs::symlink_metadata(p) else { return 0 };
        if m.nlink() > 1 && !m.is_dir() && !seen.insert((m.dev(), m.ino())) {
            return 0;
        }
        let mut n = m.blocks() * 512;
        if m.is_dir() {
            if let Ok(rd) = fs::read_dir(p) {
                n += rd.flatten().map(|e| go(&e.path(), seen)).sum::<u64>();
            }
        }
        n
    }
    go(p, &mut HashSet::new())
}
