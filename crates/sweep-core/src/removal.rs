//! Removal (§7): move an app and its selected leftovers to the Trash, with undo.
//!
//! Nothing is ever deleted permanently. Every move is written to an undo journal in
//! [`Env::state_dir`] as soon as it happens, so `undo` works even after a crash or from another process.
//! Items the user cannot move (root-owned, e.g. `/Library/LaunchDaemons/*`) are reported as
//! needing privileges; the privileged helper will handle them later (roadmap step 1b).
//!
//! The OS side (Trash, launchd, running processes) is behind [`Platform`] so tests never touch the real Trash.

use crate::env::Env;
use crate::leftovers::{is_sip_protected, Category, Report};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// What the removal needs from the operating system.
pub trait Platform {
    /// Move `p` to the Trash and return where it landed (`-[NSFileManager trashItemAtURL:…]`).
    fn trash(&self, p: &Path) -> io::Result<PathBuf>;
    /// Executable paths of all running processes.
    fn running_executables(&self) -> Vec<PathBuf>;
    /// Unload a launch agent from the user's GUI domain before its plist goes away.
    fn bootout_agent(&self, plist: &Path, label: Option<&str>);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanItem {
    pub path: PathBuf,
    pub category: Category,
    pub reason: String,
    pub size: u64,
}

/// What will be moved to the Trash. Built from a scan [`Report`] only, so it can never contain a path the
/// scanner did not find.
#[derive(Debug, Clone, Serialize)]
pub struct Plan {
    pub app_name: String,
    pub app_path: PathBuf,
    pub items: Vec<PlanItem>,
}

impl Plan {
    pub fn total_size(&self) -> u64 {
        self.items.iter().map(|i| i.size).sum()
    }
}

/// Selected findings, minus `exclude`, plus the unselected findings listed in `include`.
///
/// Both lists must name paths from the report (a typo is an error, not a silent no-op), and an item
/// cannot be kept if a folder that contains it is being removed.
pub fn plan(report: &Report, include: &[PathBuf], exclude: &[PathBuf]) -> Result<Plan> {
    if report.sip_protected {
        bail!("{} is protected by macOS and cannot be removed", report.bundle.name);
    }
    let known = |p: &PathBuf| report.findings.iter().any(|f| &f.path == p);
    for p in include.iter().chain(exclude) {
        if !known(p) {
            bail!("{} is not one of the items found for {}", p.display(), report.bundle.name);
        }
    }
    let mut items: Vec<PlanItem> = report
        .findings
        .iter()
        .filter(|f| (f.selected || include.contains(&f.path)) && !exclude.contains(&f.path))
        .map(|f| PlanItem { path: f.path.clone(), category: f.category, reason: f.reason.clone(), size: f.size })
        .collect();
    for x in exclude {
        if let Some(parent) = items.iter().find(|i| x.starts_with(&i.path)) {
            bail!("cannot keep {}: the folder containing it ({}) is being removed", x.display(), parent.path.display());
        }
    }
    // An item inside another planned folder goes with it.
    let folders: Vec<PathBuf> = items.iter().map(|i| i.path.clone()).collect();
    items.retain(|i| !folders.iter().any(|f| f != &i.path && i.path.starts_with(f)));
    Ok(Plan { app_name: report.bundle.name.clone(), app_path: report.bundle.path.clone(), items })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Moved {
    pub original: PathBuf,
    pub trashed: PathBuf,
    pub category: Category,
}

/// One removal, as recorded for undo.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Journal {
    pub id: String,
    pub app_name: String,
    pub app_path: PathBuf,
    pub created_unix: u64,
    /// Items still in the Trash, in the order they were moved.
    pub items: Vec<Moved>,
}

impl Journal {
    fn file(env: &Env, id: &str) -> PathBuf {
        env.state_dir.join("undo").join(format!("{id}.json"))
    }

    /// Written to a temp file then renamed, so a crash never leaves a half-written journal.
    fn save(&self, env: &Env) -> Result<()> {
        let path = Self::file(env, &self.id);
        if self.items.is_empty() {
            return match fs::remove_file(&path) {
                Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e.into()),
                _ => Ok(()),
            };
        }
        fs::create_dir_all(path.parent().unwrap())?;
        let tmp = path.with_extension("json.tmp");
        fs::write(&tmp, serde_json::to_vec_pretty(self)?)?;
        fs::rename(&tmp, &path).with_context(|| format!("writing undo journal {}", path.display()))
    }
}

/// Undo journals that still have items in the Trash, newest first.
pub fn journals(env: &Env) -> Vec<Journal> {
    let Ok(rd) = fs::read_dir(env.state_dir.join("undo")) else { return vec![] };
    let mut out: Vec<Journal> = rd
        .flatten()
        .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
        .filter_map(|e| serde_json::from_slice(&fs::read(e.path()).ok()?).ok())
        .collect();
    out.sort_by(|a: &Journal, b| b.created_unix.cmp(&a.created_unix).then(b.id.cmp(&a.id)));
    out
}

#[derive(Debug, Clone, Serialize)]
pub struct Problem {
    pub path: PathBuf,
    pub reason: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Outcome {
    /// Id of the undo journal (`None` when nothing was moved).
    pub journal: Option<String>,
    pub moved: Vec<Moved>,
    /// Already gone: nothing to do.
    pub missing: Vec<PathBuf>,
    /// Owned by root or another user: needs the privileged helper (not built yet).
    pub needs_privileges: Vec<Problem>,
    pub failed: Vec<Problem>,
}

/// Move everything in `plan` to the Trash (§7 step 4).
///
/// Refuses to start while a process from inside the app bundle is running, unless `allow_running`.
/// Errors on single items do not stop the others; they are reported in the [`Outcome`].
pub fn execute(plan: &Plan, env: &Env, os: &dyn Platform, allow_running: bool) -> Result<Outcome> {
    if !allow_running {
        let running: Vec<_> = os.running_executables().into_iter().filter(|p| p.starts_with(&plan.app_path)).collect();
        if !running.is_empty() {
            let names: Vec<_> = running.iter().filter_map(|p| p.file_name()).map(|n| n.to_string_lossy()).collect();
            bail!("{} is running ({}); quit it first", plan.app_name, names.join(", "));
        }
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let mut journal = Journal {
        id: format!("{}-{}", now.as_millis(), std::process::id()),
        app_name: plan.app_name.clone(),
        app_path: plan.app_path.clone(),
        created_unix: now.as_secs(),
        items: vec![],
    };
    let mut out = Outcome::default();
    let launch_agent_dirs = env.library("LaunchAgents");

    for item in &plan.items {
        let p = &item.path;
        // Defense in depth: the plan comes from the scanner, but never touch these whatever it says.
        if !p.is_absolute() || env.is_protected_root(p) || is_sip_protected(p) {
            out.failed.push(Problem { path: p.clone(), reason: "protected location, refused".into() });
            continue;
        }
        let meta = match fs::symlink_metadata(p) {
            Ok(m) => m,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                out.missing.push(p.clone());
                continue;
            }
            Err(e) => {
                out.failed.push(Problem { path: p.clone(), reason: e.to_string() });
                continue;
            }
        };
        if p.parent().is_some_and(|d| launch_agent_dirs.iter().any(|l| l == d)) {
            os.bootout_agent(p, launch_label(p).as_deref());
        }
        if let Err(e) = clear_immutable(p, &meta) {
            out.failed.push(Problem { path: p.clone(), reason: format!("locked file, could not unlock: {e}") });
            continue;
        }
        match os.trash(p) {
            Ok(trashed) => {
                let m = Moved { original: p.clone(), trashed, category: item.category };
                journal.items.push(m.clone());
                journal.save(env)?; // after every move, so undo never loses track of a file
                out.moved.push(m);
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => out.missing.push(p.clone()),
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                out.needs_privileges.push(Problem { path: p.clone(), reason: e.to_string() })
            }
            Err(e) => out.failed.push(Problem { path: p.clone(), reason: e.to_string() }),
        }
    }
    if !journal.items.is_empty() {
        out.journal = Some(journal.id);
    }
    Ok(out)
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct UndoOutcome {
    pub journal: String,
    pub restored: Vec<PathBuf>,
    /// Something already exists at the original location: left in the Trash.
    pub conflicts: Vec<PathBuf>,
    /// No longer in the Trash (emptied or moved by the user).
    pub gone: Vec<PathBuf>,
    pub failed: Vec<Problem>,
}

/// Put the items of journal `id` (default: the latest) back where they were, in reverse order.
///
/// Never overwrites anything. Items that could not be restored stay in the journal, so undo can be retried.
pub fn undo(env: &Env, id: Option<&str>) -> Result<UndoOutcome> {
    let mut journal = match id {
        Some(id) => journals(env).into_iter().find(|j| j.id == id).with_context(|| format!("no undo entry {id}"))?,
        None => journals(env).into_iter().next().context("nothing to undo")?,
    };
    let mut out = UndoOutcome { journal: journal.id.clone(), ..Default::default() };
    let mut keep = Vec::new();
    for m in journal.items.iter().rev() {
        if fs::symlink_metadata(&m.trashed).is_err() {
            out.gone.push(m.original.clone());
            continue; // dropped from the journal: nothing left to restore
        }
        if fs::symlink_metadata(&m.original).is_ok() {
            out.conflicts.push(m.original.clone());
            keep.push(m.clone());
            continue;
        }
        let res = m.original.parent().map(fs::create_dir_all).unwrap_or(Ok(())).and_then(|_| fs::rename(&m.trashed, &m.original));
        match res {
            Ok(()) => out.restored.push(m.original.clone()),
            Err(e) => {
                out.failed.push(Problem { path: m.original.clone(), reason: e.to_string() });
                keep.push(m.clone());
            }
        }
    }
    keep.reverse();
    journal.items = keep;
    journal.save(env)?;
    Ok(out)
}

/// `Label` of a launchd plist.
fn launch_label(plist: &Path) -> Option<String> {
    let v = plist::Value::from_file(plist).ok()?;
    v.as_dictionary()?.get("Label")?.as_string().map(str::to_owned)
}

const UF_IMMUTABLE: u32 = 0x0000_0002;

/// Clear the user "locked" flag (Finder's Locked checkbox), which would make the move fail.
fn clear_immutable(p: &Path, meta: &fs::Metadata) -> io::Result<()> {
    use std::os::macos::fs::MetadataExt;
    use std::os::unix::ffi::OsStrExt;
    let flags = meta.st_flags();
    if flags & UF_IMMUTABLE == 0 {
        return Ok(());
    }
    let c = std::ffi::CString::new(p.as_os_str().as_bytes()).map_err(io::Error::other)?;
    // lchflags: never follow a symlink to change the flags of its target.
    if unsafe { libc::lchflags(c.as_ptr(), flags & !UF_IMMUTABLE) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The real macOS implementation.
pub struct System;

impl Platform for System {
    fn trash(&self, p: &Path) -> io::Result<PathBuf> {
        use objc2_foundation::{NSFileManager, NSString, NSURL};
        let url = NSURL::fileURLWithPath(&NSString::from_str(&p.to_string_lossy()));
        let mut result = None;
        let fm = NSFileManager::defaultManager();
        match fm.trashItemAtURL_resultingItemURL_error(&url, Some(&mut result)) {
            Ok(()) => {
                let path = result.and_then(|u| u.path()).map(|s| PathBuf::from(s.to_string()));
                path.ok_or_else(|| io::Error::other("moved to the Trash but its new location is unknown"))
            }
            Err(e) => {
                let msg = e.localizedDescription().to_string();
                let kind = match (e.domain().to_string().as_str(), e.code()) {
                    ("NSCocoaErrorDomain", 4 | 260) => io::ErrorKind::NotFound,
                    ("NSCocoaErrorDomain", 257 | 513) => io::ErrorKind::PermissionDenied,
                    ("NSPOSIXErrorDomain", c) => io::Error::from_raw_os_error(c as i32).kind(),
                    _ => io::ErrorKind::Other,
                };
                Err(io::Error::new(kind, msg))
            }
        }
    }

    fn running_executables(&self) -> Vec<PathBuf> {
        use std::os::unix::ffi::OsStrExt;
        let n = unsafe { libc::proc_listallpids(std::ptr::null_mut(), 0) };
        if n <= 0 {
            return vec![];
        }
        let mut pids = vec![0 as libc::pid_t; n as usize + 64];
        let bytes = (pids.len() * std::mem::size_of::<libc::pid_t>()) as libc::c_int;
        let n = unsafe { libc::proc_listallpids(pids.as_mut_ptr().cast(), bytes) };
        let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
        pids.truncate(n.max(0) as usize);
        pids.into_iter()
            .filter_map(|pid| {
                let len = unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr().cast(), buf.len() as u32) };
                (len > 0).then(|| PathBuf::from(std::ffi::OsStr::from_bytes(&buf[..len as usize])))
            })
            .collect()
    }

    fn bootout_agent(&self, plist: &Path, label: Option<&str>) {
        let domain = format!("gui/{}", unsafe { libc::getuid() });
        let mut cmd = std::process::Command::new("/bin/launchctl");
        match label {
            Some(l) => cmd.args(["bootout", &format!("{domain}/{l}")]),
            None => cmd.arg("bootout").arg(&domain).arg(plist),
        };
        // Not loaded (exit 3, or 113 "could not find service") is fine: the plist is going away anyway.
        let _ = cmd.stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status();
    }
}

/// §7 step 3: without Full Disk Access, macOS blocks moving some items (other apps' containers, …).
pub fn has_full_disk_access() -> bool {
    !matches!(
        fs::File::open("/Library/Application Support/com.apple.TCC/TCC.db"),
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied
    )
}
