//! C ABI for the SwiftUI app. Every function returns a NUL-terminated JSON string, either
//! `{"ok": <value>}` or `{"error": "<message>"}`, which the caller must release with [`sweep_string_free`].
//! Panics are caught and turned into errors, so nothing unwinds into Swift.

use anyhow::{Context, Result};
use serde::Serialize;
use std::ffi::{c_char, CStr, CString};
use std::path::PathBuf;
use sweep_core::removal;
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
