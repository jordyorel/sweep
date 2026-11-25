//! String primitives used by the matchers.
//!
//! They compare names the way macOS's Foundation does (case- and diacritic-insensitive, Unicode-normalized),
//! because file names on disk and in `Info.plist` are written by Cocoa apps.

use regex::Regex;
use std::sync::OnceLock;
use unicode_normalization::{char::is_combining_mark, UnicodeNormalization};

/// Lowercase only (like `NSCaseInsensitiveSearch`).
fn lower(s: &str) -> String {
    s.to_lowercase()
}

/// Lowercase and drop diacritics (like `NSCaseInsensitiveSearch | NSDiacriticInsensitiveSearch`).
fn fold(s: &str) -> String {
    s.nfd().filter(|c| !is_combining_mark(*c)).flat_map(char::to_lowercase).collect()
}

/// Equal, ignoring case.
pub fn eq_ci(a: &str, b: &str) -> bool {
    lower(a) == lower(b)
}

/// Starts with `prefix`, ignoring case and diacritics ("Café" starts with "cafe"). An empty prefix never matches.
pub fn has_iprefix(s: &str, prefix: &str) -> bool {
    !prefix.is_empty() && fold(s).starts_with(&fold(prefix))
}

/// Contains `needle`, ignoring case. An empty needle never matches.
pub fn contains_ci(s: &str, needle: &str) -> bool {
    !needle.is_empty() && lower(s).contains(&lower(needle))
}

/// Trim whitespace, then leading/trailing dots (".Hidden." → "Hidden").
pub fn normalized(s: &str) -> String {
    s.trim().trim_matches('.').to_string()
}

/// Empty or only whitespace.
pub fn is_blank(s: &str) -> bool {
    s.trim().is_empty()
}

/// Remove spaces (only spaces: "Foo Bar" → "FooBar", the usual folder spelling of a two-word app).
pub fn remove_spaces(s: &str) -> String {
    s.replace(' ', "")
}

/// Drop a trailing number and the spaces before it ("Photoshop 2024" → "Photoshop").
pub fn strip_trailing_digits(s: &str) -> String {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\s*\d+$").unwrap()).replace(s, "").into_owned()
}

/// Number of UTF-16 code units, which is what `-[NSString length]` returns. The length thresholds of the
/// matchers (≥4, ≥8 …) are in these units, so names with accents or emoji are measured like macOS does.
pub fn ns_len(s: &str) -> usize {
    s.encode_utf16().count()
}

/// File name without its last extension (like `-stringByDeletingPathExtension`).
pub fn stem(name: &str) -> &str {
    match name.rfind('.') {
        Some(i) if i > 0 => &name[..i],
        _ => name,
    }
}

/// Extension of a file name, without the dot.
pub fn extension(name: &str) -> Option<&str> {
    match name.rfind('.') {
        Some(i) if i > 0 && i + 1 < name.len() => Some(&name[i + 1..]),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_is_case_and_diacritic_insensitive() {
        assert!(has_iprefix("Com.Foo.Bar.plist", "com.foo"));
        assert!(has_iprefix("Café Tools", "cafe"));
        assert!(!has_iprefix("x.com.foo", "com.foo"));
        assert!(!has_iprefix("anything", ""));
    }

    #[test]
    fn normalization() {
        assert_eq!(normalized("  ..Foo Bar.. "), "Foo Bar");
        assert_eq!(strip_trailing_digits("Photoshop 2024"), "Photoshop");
        assert_eq!(remove_spaces("Foo Bar Baz"), "FooBarBaz");
        assert_eq!(stem("com.foo.plist"), "com.foo");
        assert_eq!(stem(".hidden"), ".hidden");
    }
}
