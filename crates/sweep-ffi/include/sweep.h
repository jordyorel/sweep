// C ABI of crates/sweep-ffi. Every function returns JSON ({"ok": …} or {"error": "…"});
// release it with sweep_string_free.
#pragma once
#include <stdbool.h>

char *sweep_list_apps(void);
char *sweep_scan(const char *app_path);
char *sweep_remove(const char *app_path, const char *chosen_json, bool allow_running);
unsigned long long sweep_check_begin(void); // newer checks cancel older ones
char *sweep_check(const char *app_path, unsigned long long token);
char *sweep_persistence(void);
unsigned long long sweep_scan_begin(void);
void sweep_scan_cancel(void);
unsigned long long sweep_scan_progress(void);
char *sweep_scan_folder(const char *path, unsigned long long token);
char *sweep_scan_preset(const char *preset, unsigned long long token); // preset: "quick" | "full"
char *sweep_trash_findings(const char *kind, const char *paths_json); // kind: "launch_item" | "malware"
// Administrator actions (show macOS's password prompt; block until it is answered).
char *sweep_trash_privileged(const char *kind, const char *app, const char *paths_json, const char *journal);
char *sweep_undo_privileged(const char *id);
char *sweep_journals(void);
char *sweep_undo(const char *id); // NULL = latest
char *sweep_has_full_disk_access(void);
void sweep_string_free(char *s);
