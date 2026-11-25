//! Where to look. Real runs use [`Env::system`]; tests point everything at a temp dir.

use std::path::{Path, PathBuf};

/// The `/Library/<X>` folders that must never be returned as a match themselves
/// (AppCleaner's `+[ACBundle protectedPaths]`). Applied to both the user and local Library.
pub const PROTECTED_LIBRARY_DIRS: &[&str] = &[
    "Accounts", "Application Support", "Audio", "Autosave Information", "Caches", "Caches/Metadata",
    "ColorPickers", "Colors", "ColorSync", "Components", "Compositions", "Containers",
    "Contextual Menu Items", "Cookies", "CoreMediaIO", "Desktop Pictures", "Developer", "Dictionaries",
    "DirectoryServices", "Extensions", "Favorites", "Filesystems", "FontCollections", "Fonts",
    "Frameworks", "Graphics", "Group Containers", "IdentityServices", "Image Capture", "Input Methods",
    "Internet Plug-Ins", "Keyboard Layouts", "Keychains", "LanguageModeling", "LaunchAgents",
    "LaunchDaemons", "Logs", "MobileDevice", "Modem Scripts", "OpenDirectory", "PDF Services",
    "PreferencePanes", "Preferences", "Printers", "PrivilegedHelperTools", "PubSub", "QuickLook",
    "QuickTime", "Receipts", "Recent Documents", "Sandbox", "Saved Application State",
    "ScriptingAdditions", "Scripts", "Security", "Services", "Sounds", "Speech", "Spelling",
    "Spotlight", "StartupItems", "SyncedPreferences", "Video", "Voices", "WebKit", "Widgets",
];

#[derive(Debug, Clone)]
pub struct Env {
    /// `~/Library`
    pub user_library: PathBuf,
    /// `/Library`
    pub local_library: PathBuf,
    /// `/Users/Shared`
    pub users_shared: PathBuf,
    /// `/private/var/db/receipts`
    pub receipts: PathBuf,
    /// `~/Applications`, `/Applications`
    pub app_dirs: Vec<PathBuf>,
}

impl Env {
    pub fn system() -> Self {
        let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| "/var/empty".into());
        Env {
            user_library: home.join("Library"),
            local_library: "/Library".into(),
            users_shared: "/Users/Shared".into(),
            receipts: "/private/var/db/receipts".into(),
            app_dirs: vec![home.join("Applications"), "/Applications".into()],
        }
    }

    /// Everything rooted under `root` (for tests).
    pub fn rooted(root: &Path) -> Self {
        Env {
            user_library: root.join("Users/me/Library"),
            local_library: root.join("Library"),
            users_shared: root.join("Users/Shared"),
            receipts: root.join("private/var/db/receipts"),
            app_dirs: vec![root.join("Users/me/Applications"), root.join("Applications")],
        }
    }

    fn libs(&self) -> [&Path; 2] {
        [&self.user_library, &self.local_library]
    }

    /// `libraryPaths` / `libraryPathsByAppendingPathComponent:`
    pub fn library(&self, sub: &str) -> Vec<PathBuf> {
        self.libs().iter().map(|l| if sub.is_empty() { l.to_path_buf() } else { l.join(sub) }).collect()
    }

    /// `cachesPathsByAppendingPathComponent:`
    pub fn caches(&self, sub: &str) -> Vec<PathBuf> {
        self.library(&join("Caches", sub))
    }

    /// `appSupportPathsByAppendingPathComponent:`
    pub fn app_support(&self, sub: &str) -> Vec<PathBuf> {
        self.library(&join("Application Support", sub))
    }

    pub fn is_protected_root(&self, p: &Path) -> bool {
        self.libs().iter().any(|l| PROTECTED_LIBRARY_DIRS.iter().any(|d| p == l.join(d)))
    }
}

fn join(a: &str, b: &str) -> String {
    if b.is_empty() { a.to_string() } else { format!("{a}/{b}") }
}
