//! `sweep`: uninstall-leftover finder and on-demand malware checks for macOS.
//! Everything here is read-only: nothing is moved or deleted yet.

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
use sweep_core::{Env, Options};
use sweep_malware::{persistence, signing, xprotect};

#[derive(Parser)]
#[command(name = "sweep", version, about = "Find app leftovers and check for malware on macOS (read-only)")]
struct Cli {
    /// Print JSON instead of text.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// List installed apps.
    List,
    /// Show everything that would be removed with an app (dry run).
    Leftovers {
        app: PathBuf,
        /// Skip reading App Group entitlements (faster).
        #[arg(long)]
        no_entitlements: bool,
    },
    /// Scan files or folders with Apple's XProtect malware signatures.
    Malware {
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        /// Skip files larger than this many MB.
        #[arg(long, default_value_t = 128)]
        max_size_mb: u64,
    },
    /// Audit launch agents and daemons for malware red flags.
    Persistence {
        /// Also show jobs with no red flags.
        #[arg(long)]
        all: bool,
        /// Skip signature scanning of each job's program.
        #[arg(long)]
        no_yara: bool,
    },
    /// Security check of one app: signature, notarization, quarantine, malware signatures.
    Check { app: PathBuf },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let env = Env::system();
    match cli.cmd {
        Cmd::List => {
            let apps = sweep_core::list_apps(&env);
            if cli.json {
                return print_json(&apps);
            }
            for a in &apps {
                println!("{:<40} {:<14} {}", a.name, a.version, a.raw_id.as_deref().unwrap_or("-"));
            }
            eprintln!("{} apps", apps.len());
        }
        Cmd::Leftovers { app, no_entitlements } => {
            let report = sweep_core::scan(&app, &env, &Options { read_entitlements: !no_entitlements, sizes: true })?;
            if cli.json {
                return print_json(&report);
            }
            let b = &report.bundle;
            println!("{} {}  ({})", b.name, b.version, b.raw_id.as_deref().unwrap_or("no bundle id"));
            if !report.nested.is_empty() {
                let ids: Vec<_> = report.nested.iter().filter_map(|n| n.id.as_deref()).collect();
                println!("nested helpers: {}", ids.join(", "));
            }
            if report.sip_protected {
                println!("!! protected by macOS: cannot be removed");
            }
            println!();
            for f in &report.findings {
                let mark = if f.selected { "[x]" } else { "[ ]" };
                let via = f.via.as_deref().map(|v| format!(" (via {v})")).unwrap_or_default();
                println!("{mark} {:>9}  {:<20} {}", human(f.size), format!("{:?}", f.category), tilde(&f.path));
                println!("    {:>9}  {}{via}", "", f.reason);
            }
            let sel: u64 = report.findings.iter().filter(|f| f.selected).map(|f| f.size).sum();
            println!("\n{} items, {} selected ({})", report.findings.len(), report.findings.iter().filter(|f| f.selected).count(), human(sel));
        }
        Cmd::Malware { paths, max_size_mb } => {
            let (version, sum) = xprotect::scan_paths(&paths, max_size_mb * 1024 * 1024)?;
            if cli.json {
                return print_json(&serde_json::json!({ "xprotect_version": version, "summary": sum }));
            }
            println!("XProtect rules version {version}");
            println!("{} files scanned, {} skipped, {} errors", sum.files_scanned, sum.files_skipped, sum.errors.len());
            if sum.detections.is_empty() {
                println!("no known malware found");
            }
            for d in &sum.detections {
                println!("!! {}  {}", d.rule, tilde(&d.path));
                if let Some(desc) = &d.description {
                    println!("   {desc}");
                }
            }
        }
        Cmd::Persistence { all, no_yara } => {
            let rules = if no_yara { None } else { Some(xprotect::Rules::load_system()?) };
            let home = home();
            let jobs = persistence::audit(&home, rules.as_ref());
            if cli.json {
                return print_json(&jobs);
            }
            let total = jobs.len();
            for j in jobs.iter().filter(|j| all || j.risk > persistence::Risk::Info) {
                let who = j.signature.as_ref().and_then(|s| s.authority.first().cloned()).unwrap_or_else(|| "unsigned".into());
                println!("[{:?}] {}", j.risk, tilde(&j.plist));
                println!("    program: {}", j.program.as_deref().map(tilde).unwrap_or_else(|| "-".into()));
                println!("    signer:  {who}");
                for f in &j.flags {
                    println!("    - {f}");
                }
            }
            let flagged = jobs.iter().filter(|j| j.risk > persistence::Risk::Info).count();
            println!("\n{total} launch jobs, {flagged} with red flags");
        }
        Cmd::Check { app } => {
            let sig = signing::inspect(&app);
            let quarantined = signing::is_quarantined(&app);
            let (version, sum) = xprotect::scan_paths(std::slice::from_ref(&app), xprotect::DEFAULT_MAX_FILE_SIZE)?;
            if cli.json {
                return print_json(&serde_json::json!({
                    "signature": sig, "quarantined": quarantined, "xprotect_version": version, "scan": sum,
                }));
            }
            println!("{}", app.display());
            println!("  signature:   {:?}{}", sig.status, if sig.adhoc { " (ad-hoc)" } else { "" });
            println!("  signer:      {}", sig.authority.first().map(String::as_str).unwrap_or("-"));
            println!("  team id:     {}", sig.team_id.as_deref().unwrap_or("-"));
            if let Some(g) = &sig.gatekeeper {
                println!("  gatekeeper:  {} ({})", if g.accepted { "accepted" } else { "REJECTED" }, g.source);
            }
            println!("  quarantined: {quarantined}");
            println!("  malware:     {} files scanned with XProtect {version}, {} detections", sum.files_scanned, sum.detections.len());
            for d in &sum.detections {
                println!("    !! {}  {}", d.rule, d.path.display());
            }
        }
    }
    Ok(())
}

fn print_json<T: serde::Serialize>(v: &T) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(v)?);
    Ok(())
}

fn home() -> PathBuf {
    std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| "/var/empty".into())
}

fn tilde(p: &Path) -> String {
    let s = p.display().to_string();
    match std::env::var("HOME") {
        Ok(h) if s.starts_with(&h) => format!("~{}", &s[h.len()..]),
        _ => s,
    }
}

fn human(n: u64) -> String {
    const U: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1000.0 && i < U.len() - 1 {
        v /= 1000.0;
        i += 1;
    }
    if i == 0 { format!("{n} B") } else { format!("{v:.1} {}", U[i]) }
}
