//! Removal and undo against a fake Trash in a temp dir: the real Trash is never touched.

use std::cell::RefCell;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use sweep_core::removal::{self, Platform};
use sweep_core::{scan, Category, Env, Options};

struct FakeOs {
    trash: PathBuf,
    running: Vec<PathBuf>,
    /// Paths under these behave as root-owned.
    root_owned: Vec<PathBuf>,
    booted_out: RefCell<Vec<String>>,
}

impl FakeOs {
    fn new(root: &Path) -> Self {
        let trash = root.join("Users/me/.Trash");
        fs::create_dir_all(&trash).unwrap();
        FakeOs { trash, running: vec![], root_owned: vec![], booted_out: RefCell::new(vec![]) }
    }
}

impl Platform for FakeOs {
    fn trash(&self, p: &Path) -> io::Result<PathBuf> {
        if self.root_owned.iter().any(|r| p.starts_with(r)) {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "you don't have permission"));
        }
        let name = p.file_name().unwrap().to_string_lossy().into_owned();
        let mut dst = self.trash.join(&name);
        let mut n = 2;
        while dst.exists() {
            dst = self.trash.join(format!("{name} {n}"));
            n += 1;
        }
        fs::rename(p, &dst)?;
        Ok(dst)
    }
    fn running_executables(&self) -> Vec<PathBuf> {
        self.running.clone()
    }
    fn bootout_agent(&self, plist: &Path, label: Option<&str>) {
        self.booted_out.borrow_mut().push(label.map(str::to_owned).unwrap_or_else(|| plist.display().to_string()));
    }
}

fn write(p: &Path, s: &str) {
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, s).unwrap();
}

/// `Applications/Foo Bar/Foo Bar.app` with a few leftovers. Returns (app, leftovers).
fn fixture(env: &Env, root: &Path) -> (PathBuf, Vec<PathBuf>) {
    let app = root.join("Applications/Foo Bar/Foo Bar.app");
    write(
        &app.join("Contents/Info.plist"),
        r#"<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>com.example.foobar</string>
<key>CFBundleName</key><string>Foo Bar</string>
<key>CFBundleExecutable</key><string>Foo Bar</string>
</dict></plist>"#,
    );
    write(&app.join("Contents/MacOS/Foo Bar"), "bin");
    let ul = &env.user_library;
    let agent = ul.join("LaunchAgents/com.example.foobar.agent.plist");
    write(
        &agent,
        r#"<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict>
<key>Label</key><string>com.example.foobar.agent</string></dict></plist>"#,
    );
    let leftovers = vec![
        ul.join("Preferences/com.example.foobar.plist"),
        ul.join("Application Support/Foo Bar/data.db"),
        ul.join("Caches/com.example.foobar/blob"),
        agent,
    ];
    for p in &leftovers[..3] {
        write(p, "x");
    }
    (app, leftovers)
}

fn setup() -> (tempfile::TempDir, Env, PathBuf, Vec<PathBuf>) {
    let tmp = tempfile::tempdir().unwrap();
    let env = Env::rooted(tmp.path());
    let (app, leftovers) = fixture(&env, tmp.path());
    (tmp, env, app, leftovers)
}

#[test]
fn plan_takes_selected_items_and_validates_overrides() {
    let (tmp, env, app, _) = setup();
    let report = scan(&app, &env, &Options::default()).unwrap();
    let parent = tmp.path().join("Applications/Foo Bar");

    let p = removal::plan(&report, &[], &[]).unwrap();
    assert_eq!(p.items[0].path, app);
    assert!(!p.items.iter().any(|i| i.path == parent), "parent folder is never pre-selected");

    // Including the parent folder swallows the app inside it.
    let p = removal::plan(&report, std::slice::from_ref(&parent), &[]).unwrap();
    assert!(p.items.iter().any(|i| i.path == parent));
    assert!(!p.items.iter().any(|i| i.path == app));

    // Paths must come from the scan.
    assert!(removal::plan(&report, &[], &[tmp.path().join("nope")]).is_err());
    assert!(removal::plan(&report, &[env.user_library.join("Keychains")], &[]).is_err());
    // Cannot keep the app while trashing the folder that contains it.
    assert!(removal::plan(&report, std::slice::from_ref(&parent), std::slice::from_ref(&app)).is_err());
}

#[test]
fn remove_then_undo_round_trip() {
    let (tmp, env, app, leftovers) = setup();
    let os = FakeOs::new(tmp.path());
    let report = scan(&app, &env, &Options::default()).unwrap();
    let plan = removal::plan(&report, &[], &[]).unwrap();

    let out = removal::execute(&plan, &env, &os, false).unwrap();
    assert!(out.failed.is_empty() && out.needs_privileges.is_empty(), "{out:#?}");
    assert!(!app.exists());
    for l in &leftovers {
        assert!(!l.exists(), "{l:?} still there");
    }
    assert!(out.moved.iter().all(|m| m.trashed.starts_with(&os.trash) && m.trashed.exists()));
    assert_eq!(*os.booted_out.borrow(), vec!["com.example.foobar.agent".to_string()]);
    assert!(out.moved.iter().any(|m| m.category == Category::LaunchAgents));

    let journals = removal::journals(&env);
    assert_eq!(journals.len(), 1);
    assert_eq!(Some(&journals[0].id), out.journal.as_ref());

    let u = removal::undo(&env, None).unwrap();
    assert!(u.failed.is_empty() && u.conflicts.is_empty() && u.gone.is_empty(), "{u:#?}");
    assert!(app.join("Contents/MacOS/Foo Bar").exists());
    for l in &leftovers {
        assert!(l.exists(), "{l:?} not restored");
    }
    assert!(removal::journals(&env).is_empty(), "journal should be cleared once everything is back");
    assert!(removal::undo(&env, None).is_err());
}

#[test]
fn refuses_while_the_app_runs() {
    let (tmp, env, app, _) = setup();
    let mut os = FakeOs::new(tmp.path());
    os.running = vec![app.join("Contents/MacOS/Foo Bar")];
    let plan = removal::plan(&scan(&app, &env, &Options::default()).unwrap(), &[], &[]).unwrap();
    let err = removal::execute(&plan, &env, &os, false).unwrap_err();
    assert!(err.to_string().contains("running"), "{err}");
    assert!(app.exists());
    // A look-alike path outside the bundle is not "the app running".
    os.running = vec![tmp.path().join("Applications/Foo Bar/Foo Bar.app.old/x")];
    assert!(removal::execute(&plan, &env, &os, false).is_ok());
}

#[test]
fn root_owned_items_are_reported_not_fatal() {
    let (tmp, env, app, _) = setup();
    let daemon = env.local_library.join("LaunchDaemons/com.example.foobar.helper.plist");
    write(&daemon, "x");
    let mut os = FakeOs::new(tmp.path());
    os.root_owned = vec![env.local_library.join("LaunchDaemons")];
    let plan = removal::plan(&scan(&app, &env, &Options::default()).unwrap(), &[], &[]).unwrap();
    let out = removal::execute(&plan, &env, &os, false).unwrap();
    assert_eq!(out.needs_privileges.len(), 1);
    assert_eq!(out.needs_privileges[0].path, daemon);
    assert!(daemon.exists());
    assert!(!app.exists(), "the rest still goes");
}

#[test]
fn undo_never_overwrites() {
    let (tmp, env, app, leftovers) = setup();
    let os = FakeOs::new(tmp.path());
    let plan = removal::plan(&scan(&app, &env, &Options::default()).unwrap(), &[], &[]).unwrap();
    removal::execute(&plan, &env, &os, false).unwrap();

    // The user reinstalled preferences meanwhile.
    write(&leftovers[0], "new");
    let u = removal::undo(&env, None).unwrap();
    assert_eq!(u.conflicts, vec![leftovers[0].clone()]);
    assert_eq!(fs::read_to_string(&leftovers[0]).unwrap(), "new");
    assert!(app.exists());
    // The conflicting item stays in the journal for a later retry.
    let j = removal::journals(&env);
    assert_eq!(j.len(), 1);
    assert_eq!(j[0].items.len(), 1);
}

#[test]
fn locked_files_are_unlocked_first() {
    use std::os::unix::ffi::OsStrExt;
    let (tmp, env, app, leftovers) = setup();
    let prefs = &leftovers[0];
    let c = std::ffi::CString::new(prefs.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::chflags(c.as_ptr(), 0x2) }, 0); // UF_IMMUTABLE, like Finder's "Locked"
    let os = FakeOs::new(tmp.path());
    let plan = removal::plan(&scan(&app, &env, &Options::default()).unwrap(), &[], &[]).unwrap();
    let out = removal::execute(&plan, &env, &os, false).unwrap();
    assert!(out.failed.is_empty(), "{out:#?}");
    assert!(!prefs.exists());
}
