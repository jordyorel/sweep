//! Core of the uninstaller: read a bundle, find what it left behind.

pub mod bundle;
pub mod env;
pub mod leftovers;
pub mod text;

pub use bundle::{Bundle, BundleKind};
pub use env::Env;
pub use leftovers::{scan, Category, Finding, Options, Report};

/// Applications in the standard folders (`~/Applications`, `/Applications`), up to 3 levels deep,
/// sorted by name. Mirrors the "app list" view.
pub fn list_apps(env: &Env) -> Vec<Bundle> {
    fn visit(dir: &std::path::Path, level: usize, out: &mut Vec<Bundle>) {
        let Ok(rd) = std::fs::read_dir(dir) else { return };
        for e in rd.flatten() {
            let p = e.path();
            if p.extension().is_some_and(|x| x.eq_ignore_ascii_case("app")) {
                if let Ok(b) = Bundle::open(&p) {
                    out.push(b);
                }
            } else if e.file_type().map(|t| t.is_dir()).unwrap_or(false) && level < 3 {
                visit(&p, level + 1, out);
            }
        }
    }
    let mut out = Vec::new();
    for d in &env.app_dirs {
        visit(d, 1, &mut out);
    }
    out.sort_by_key(|b| b.name.to_lowercase());
    out
}
