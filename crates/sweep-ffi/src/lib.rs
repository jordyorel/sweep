//! C ABI for the SwiftUI app. Every function returns a NUL-terminated JSON string, either
//! `{"ok": <value>}` or `{"error": "<message>"}`, which the caller must release with [`sweep_string_free`].
//! Panics are caught and turned into errors, so nothing unwinds into Swift.

use anyhow::{Context, Result};
use serde::Serialize;
use std::ffi::{c_char, CStr, CString};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use sweep_malware::xprotect::{Rules, ScanSummary, DEFAULT_MAX_FILE_SIZE};
use sweep_malware::presets::{self, Preset};
use sweep_malware::{check, persistence};
use sweep_core::removal::{self, Plan, PlanItem};
use sweep_core::Category;
use sweep_core::{Env, Options};

fn respond<T: Serialize>(f: impl FnOnce() -> Result<T> + std::panic::UnwindSafe) -> *mut c_char {
    let json = match std::panic::catch_unwind(f) {
        Ok(Ok(v)) => serde_json::json!({ "ok": v }),
        Ok(Err(e)) => serde_json::json!({ "error": format!("{e:#}") }),
        Err(_) => serde_json::json!({ "error": "internal error (panic)" }),
    };
    // serde_json never emits a NUL byte, so this cannot fail.
    CString::new(json.to_string()).unwrap_or_default().into_raw()
}

/// # Safety
/// `p` must be NULL or a valid NUL-terminated string.
unsafe fn arg(p: *const c_char) -> Result<Option<String>> {
    if p.is_null() {
        return Ok(None);
    }
    Ok(Some(unsafe { CStr::from_ptr(p) }.to_str().context("argument is not UTF-8")?.to_owned()))
}

/// Installed apps (`[Bundle]`).
#[no_mangle]
pub extern "C" fn sweep_list_apps() -> *mut c_char {
    respond(|| Ok(sweep_core::list_apps(&Env::system())))
}

/// Everything related to the app at `app_path` (`Report`).
///
/// # Safety
/// `app_path` must be a valid NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn sweep_scan(app_path: *const c_char) -> *mut c_char {
    let app = unsafe { arg(app_path) };
    respond(move || {
        let app = PathBuf::from(app?.context("missing app path")?);
        sweep_core::scan(&app, &Env::system(), &Options { read_entitlements: true, sizes: true })
    })
}

/// Move the app and the chosen items (`chosen_json`: JSON array of paths, as shown to the user) to the Trash
/// (`Outcome`). The app is scanned again and only paths from that scan can be removed; anything new that
/// appeared since the user looked is kept.
///
/// # Safety
/// Both arguments must be valid NUL-terminated strings.
#[no_mangle]
pub unsafe extern "C" fn sweep_remove(app_path: *const c_char, chosen_json: *const c_char, allow_running: bool) -> *mut c_char {
    let (app, chosen) = unsafe { (arg(app_path), arg(chosen_json)) };
    respond(move || {
        let app = PathBuf::from(app?.context("missing app path")?);
        let chosen: Vec<PathBuf> = serde_json::from_str(&chosen?.context("missing selection")?)?;
        let env = Env::system();
        let report = sweep_core::scan(&app, &env, &Options { read_entitlements: true, sizes: true })?;
        let (include, exclude) = overrides(&report, &chosen)?;
        let plan = removal::plan(&report, &include, &exclude)?;
        removal::execute(&plan, &env, &removal::System, allow_running)
    })
}

/// Turn "what the user ticked" into include/exclude relative to the default selection.
fn overrides(report: &sweep_core::Report, chosen: &[PathBuf]) -> Result<(Vec<PathBuf>, Vec<PathBuf>)> {
    for c in chosen {
        anyhow::ensure!(report.findings.iter().any(|f| &f.path == c), "{} is no longer found for this app; scan again", c.display());
    }
    let inside_chosen = |p: &PathBuf| chosen.iter().any(|c| c != p && p.starts_with(c));
    let include = report.findings.iter().filter(|f| !f.selected && chosen.contains(&f.path)).map(|f| f.path.clone()).collect();
    let exclude = report
        .findings
        .iter()
        .filter(|f| f.selected && !chosen.contains(&f.path) && !inside_chosen(&f.path))
        .map(|f| f.path.clone())
        .collect();
    Ok((include, exclude))
}

/// XProtect rules are compiled once per process (about a second); errors are kept so they are reported each time.
fn rules() -> Result<&'static Rules> {
    static RULES: OnceLock<std::result::Result<Rules, String>> = OnceLock::new();
    RULES.get_or_init(|| Rules::load_system().map_err(|e| format!("{e:#}"))).as_ref().map_err(|e| anyhow::anyhow!("{e}"))
}

/// Latest check token: a check stops as soon as a newer one has started (the user picked another app).
static CHECK_TOKEN: AtomicU64 = AtomicU64::new(0);

/// Start a new check: returns its token and makes every older check stop early.
#[no_mangle]
pub extern "C" fn sweep_check_begin() -> u64 {
    CHECK_TOKEN.fetch_add(1, Ordering::SeqCst) + 1
}

/// Security check of one app (`AppCheck`): signature, notarization, quarantine, XProtect signatures.
/// Slow on big apps; returns early with `scan.cancelled` once a newer [`sweep_check_begin`] happens.
///
/// # Safety
/// `app_path` must be a valid NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn sweep_check(app_path: *const c_char, token: u64) -> *mut c_char {
    let app = unsafe { arg(app_path) };
    respond(move || {
        let app = PathBuf::from(app?.context("missing app path")?);
        let stale = || CHECK_TOKEN.load(Ordering::SeqCst) != token;
        Ok(check::app(&app, rules()?, &stale))
    })
}

/// Launch agents and daemons with their red flags, riskiest first (`[LaunchJob]`).
#[no_mangle]
pub extern "C" fn sweep_persistence() -> *mut c_char {
    respond(|| {
        let mut jobs = persistence::audit(&home(), Some(rules()?));
        // Sweep's own watch agent (installed from this app bundle) is not a finding.
        let own_plist = home().join("Library/LaunchAgents/dev.sweep.watch.plist");
        let own_helper = std::env::current_exe().ok().and_then(|e| Some(e.parent()?.parent()?.join("Helpers/sweep")));
        for j in &mut jobs {
            if j.plist == own_plist && j.program.is_some() && j.program == own_helper {
                j.risk = persistence::Risk::Info;
                j.flags = vec!["Sweep's own background watch (turn it off with the switch in the sidebar)".into()];
            }
        }
        jobs.sort_by(|a, b| b.risk.cmp(&a.risk).then_with(|| a.plist.cmp(&b.plist)));
        Ok(jobs)
    })
}

/// Latest folder-scan token (a newer scan, or [`sweep_scan_cancel`], stops the running one) and its progress.
static SCAN_TOKEN: AtomicU64 = AtomicU64::new(0);
static SCAN_PROGRESS: AtomicU64 = AtomicU64::new(0);

#[no_mangle]
pub extern "C" fn sweep_scan_begin() -> u64 {
    SCAN_PROGRESS.store(0, Ordering::SeqCst);
    SCAN_TOKEN.fetch_add(1, Ordering::SeqCst) + 1
}

/// Stop the running folder scan; it returns what it found so far with `cancelled: true`.
#[no_mangle]
pub extern "C" fn sweep_scan_cancel() {
    SCAN_TOKEN.fetch_add(1, Ordering::SeqCst);
}

/// Items (files and folders) visited so far by the running folder scan.
#[no_mangle]
pub extern "C" fn sweep_scan_progress() -> u64 {
    SCAN_PROGRESS.load(Ordering::SeqCst)
}

#[derive(serde::Serialize)]
struct FolderScan {
    path: PathBuf,
    xprotect_version: String,
    summary: ScanSummary,
}

/// Scan a file or folder with XProtect's signatures (`FolderScan`). Blocking; see [`sweep_scan_begin`].
///
/// # Safety
/// `path` must be a valid NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn sweep_scan_folder(path: *const c_char, token: u64) -> *mut c_char {
    let path = unsafe { arg(path) };
    respond(move || {
        let path = PathBuf::from(path?.context("missing path")?);
        let rules = rules()?;
        let mut summary = ScanSummary::default();
        let stop = || {
            SCAN_PROGRESS.fetch_add(1, Ordering::Relaxed);
            SCAN_TOKEN.load(Ordering::SeqCst) != token
        };
        rules.scan_until(&path, DEFAULT_MAX_FILE_SIZE, &mut summary, &stop);
        Ok(FolderScan { path, xprotect_version: rules.version.clone(), summary })
    })
}

/// Quick or full scan (`FolderScan`, whose `path` is the preset's title). `preset`: `quick` or `full`.
/// Cancellable and reports progress like [`sweep_scan_folder`].
///
/// # Safety
/// `preset` must be a valid NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn sweep_scan_preset(preset: *const c_char, token: u64) -> *mut c_char {
    let preset = unsafe { arg(preset) };
    respond(move || {
        let name = preset?.context("missing preset")?;
        let p = Preset::parse(&name).with_context(|| format!("unknown scan preset {name}"))?;
        let rules = rules()?;
        let mut summary = ScanSummary::default();
        let stop = || {
            SCAN_PROGRESS.fetch_add(1, Ordering::Relaxed);
            SCAN_TOKEN.load(Ordering::SeqCst) != token
        };
        for t in presets::targets(p, &home()) {
            rules.scan_until(&t, DEFAULT_MAX_FILE_SIZE, &mut summary, &stop);
            if summary.cancelled {
                break;
            }
        }
        Ok(FolderScan { path: PathBuf::from(p.title()), xprotect_version: rules.version.clone(), summary })
    })
}

/// Move security findings to the Trash, with undo (`Outcome`). `kind` is `launch_item` or `malware`.
///
/// Each path is re-checked first, so a stale or forged list cannot trash arbitrary files:
/// a launch item must still be a plist in one of the launch folders, a malware file must still match
/// an XProtect signature right now.
///
/// # Safety
/// Both arguments must be valid NUL-terminated strings.
#[no_mangle]
pub unsafe extern "C" fn sweep_trash_findings(kind: *const c_char, paths_json: *const c_char) -> *mut c_char {
    let (kind, paths) = unsafe { (arg(kind), arg(paths_json)) };
    respond(move || {
        let kind = kind?.context("missing kind")?;
        let paths: Vec<PathBuf> = serde_json::from_str(&paths?.context("missing paths")?)?;
        anyhow::ensure!(!paths.is_empty(), "nothing to move");
        let home = home();
        let mut items = Vec::new();
        for p in &paths {
            let (category, reason) = match kind.as_str() {
                "launch_item" => {
                    let (_, daemon) = persistence::job_plists(&home)
                        .into_iter()
                        .find(|(j, _)| j == p)
                        .with_context(|| format!("{} is not a launch item (any more)", p.display()))?;
                    (if daemon { Category::LaunchDaemons } else { Category::LaunchAgents }, "launch item flagged by the audit")
                }
                "malware" => {
                    let mut s = ScanSummary::default();
                    rules()?.scan(p, DEFAULT_MAX_FILE_SIZE, &mut s);
                    anyhow::ensure!(!s.detections.is_empty(), "{} no longer matches a malware signature", p.display());
                    (Category::Other, "matches an XProtect malware signature")
                }
                other => anyhow::bail!("unknown kind {other}"),
            };
            items.push(PlanItem { path: p.clone(), category, reason: reason.into(), size: sweep_core::leftovers::allocated_size(p) });
        }
        let name = match kind.as_str() {
            "launch_item" => "Launch items",
            _ => "Malware",
        };
        let plan = Plan { app_name: name.into(), app_path: paths[0].clone(), items };
        // allow_running: there is no app bundle here; a running daemon is booted out by launchd rules, not by us.
        removal::execute(&plan, &Env::system(), &removal::System, true)
    })
}

fn home() -> PathBuf {
    std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| "/var/empty".into())
}

/// Removals that can still be undone, newest first (`[Journal]`).
#[no_mangle]
pub extern "C" fn sweep_journals() -> *mut c_char {
    respond(|| Ok(removal::journals(&Env::system())))
}

/// Undo journal `id`, or the latest when NULL (`UndoOutcome`).
///
/// # Safety
/// `id` must be NULL or a valid NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn sweep_undo(id: *const c_char) -> *mut c_char {
    let id = unsafe { arg(id) };
    respond(move || removal::undo(&Env::system(), id?.as_deref()))
}

/// Whether this process has Full Disk Access (`bool`).
#[no_mangle]
pub extern "C" fn sweep_has_full_disk_access() -> *mut c_char {
    respond(|| Ok(removal::has_full_disk_access()))
}

/// Release a string returned by any `sweep_*` function.
///
/// # Safety
/// `s` must come from this library and not have been freed already.
#[no_mangle]
pub unsafe extern "C" fn sweep_string_free(s: *mut c_char) {
    if !s.is_null() {
        drop(unsafe { CString::from_raw(s) });
    }
}
