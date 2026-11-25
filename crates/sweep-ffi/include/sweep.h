// C ABI of crates/sweep-ffi. Every function returns JSON ({"ok": …} or {"error": "…"});
// release it with sweep_string_free.
#pragma once
#include <stdbool.h>

char *sweep_list_apps(void);
char *sweep_scan(const char *app_path);
char *sweep_remove(const char *app_path, const char *chosen_json, bool allow_running);
unsigned long long sweep_check_begin(void); // newer checks cancel older ones
char *sweep_check(const char *app_path, unsigned long long token);
char *sweep_journals(void);
char *sweep_undo(const char *id); // NULL = latest
char *sweep_has_full_disk_access(void);
void sweep_string_free(char *s);
