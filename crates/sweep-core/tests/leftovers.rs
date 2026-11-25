use std::fs;
use std::path::Path;
use sweep_core::{scan, Category, Env, Options};

fn touch(p: &Path) {
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, b"x").unwrap();
}

fn mkdir(p: &Path) {
    fs::create_dir_all(p).unwrap();
}

fn info_plist(dir: &Path, id: &str, name: &str, extra: &str) {
    touch(&dir.join("Contents/Info.plist"));
    fs::write(
        dir.join("Contents/Info.plist"),
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>{id}</string>
<key>CFBundleName</key><string>{name}</string>
<key>CFBundleExecutable</key><string>{name}</string>
<key>CFBundleShortVersionString</key><string>1.2.3</string>
{extra}
</dict></plist>"#
        ),
    )
    .unwrap();
}

#[test]
fn finds_leftovers_and_skips_lookalikes() {
    let tmp = tempfile::tempdir().unwrap();
    let r = tmp.path();
    let env = Env::rooted(r);
    let ul = &env.user_library;

    // The app, in its own folder, with a nested helper and an embedded Automator service.
    let app = r.join("Applications/Foo Bar/Foo Bar.app");
    info_plist(
        &app,
        "com.example.foobar",
        "Foo Bar",
        "<key>SMPrivilegedExecutables</key><dict><key>com.example.foobar.helper</key><string>x</string></dict>",
    );
    info_plist(&app.join("Contents/Library/LoginItems/Foo Helper.app"), "com.example.foohelper", "Foo Helper", "");
    mkdir(&app.join("Contents/Resources/Convert With Foo.workflow"));

    // Should match.
    let want = [
        (ul.join("Preferences/com.example.foobar.plist"), Category::Preferences),
        (ul.join("Preferences/ByHost/com.example.foobar.ABCD.plist"), Category::Preferences),
        (ul.join("Application Support/Foo Bar"), Category::ApplicationSupport),
        (ul.join("Application Support/FooBar-2"), Category::ApplicationSupport),
        (ul.join("Caches/com.example.foobar"), Category::Caches),
        (ul.join("Containers/com.example.foobar"), Category::Containers),
        (ul.join("Saved Application State/com.example.foobar.savedState"), Category::SavedState),
        (ul.join("HTTPStorages/com.example.foobar"), Category::WebData),
        (ul.join("Logs/Foo Bar"), Category::Logs),
        (ul.join("Logs/DiagnosticReports/Foo Bar_2026-01-01.ips"), Category::CrashReports),
        (ul.join("LaunchAgents/com.example.foobar.agent.plist"), Category::LaunchAgents),
        (ul.join("Services/Convert With Foo.workflow"), Category::Services),
        (env.local_library.join("LaunchDaemons/com.example.foobar.helper.plist"), Category::LaunchDaemons),
        (env.local_library.join("PrivilegedHelperTools/com.example.foobar.helper"), Category::PrivilegedHelpers),
        (env.receipts.join("com.example.foobar.pkg.bom"), Category::Receipts),
        // Found through the nested helper's bundle id.
        (ul.join("Preferences/com.example.foohelper.plist"), Category::Preferences),
    ];
    // Must NOT match.
    let traps = [
        ul.join("Application Support/Foo Barista"), // letter after the name
        ul.join("Application Support/MyFoo Bar"),   // name not at the start
        ul.join("Preferences/com.example.foobarista.plist").with_file_name("com.other.plist"),
        ul.join("Logs/Foo Helper"), // nested helpers match by id only, not by name
    ];
    for (p, _) in &want {
        if p.extension().is_some() && !p.to_string_lossy().ends_with(".workflow") { touch(p) } else { mkdir(p) }
    }
    for p in &traps {
        mkdir(p);
    }
    // Protected roots are never returned, even though the name would match the id rule.
    mkdir(&ul.join("Preferences"));

    let report = scan(&app, &env, &Options::default()).unwrap();
    let got: Vec<_> = report.findings.iter().map(|f| (f.path.clone(), f.category)).collect();

    assert_eq!(report.bundle.name, "Foo Bar");
    assert_eq!(report.nested.len(), 1);
    assert_eq!(report.findings[0].category, Category::Bundle);
    for w in &want {
        assert!(got.contains(w), "missing {:?}\n got: {got:#?}", w);
    }
    for t in &traps {
        assert!(!got.iter().any(|(p, _)| p == t), "false positive {t:?}");
    }
    // Parent folder is suggested but not pre-selected.
    let parent = report.findings.iter().find(|f| f.category == Category::ParentFolder).unwrap();
    assert_eq!(parent.path, r.join("Applications/Foo Bar"));
    assert!(!parent.selected);
}

#[test]
fn short_names_need_an_exact_match() {
    let tmp = tempfile::tempdir().unwrap();
    let r = tmp.path();
    let env = Env::rooted(r);
    let app = r.join("Applications/Fox.app");
    info_plist(&app, "io.fox", "Fox", "");
    mkdir(&env.user_library.join("Application Support/Fox"));
    mkdir(&env.user_library.join("Application Support/Fox-data")); // short name: regex not used
    let report = scan(&app, &env, &Options::default()).unwrap();
    let paths: Vec<_> = report.findings.iter().map(|f| f.path.file_name().unwrap().to_owned()).collect();
    assert!(paths.contains(&"Fox".into()));
    assert!(!paths.contains(&"Fox-data".into()));
}
