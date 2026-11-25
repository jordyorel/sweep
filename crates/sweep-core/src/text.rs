//! String primitives used by the matchers.
//!
//! Each function mirrors the Foundation call AppCleaner uses, so the matching
//! behaves the same way (see `docs/appcleaner-internals.md` §4).

use regex::Regex;
use std::sync::OnceLock;
use unicode_normalization::{char::is_combining_mark, UnicodeNormalization};

/// Lowercase only (`caseInsensitiveCompare` / `NSCaseInsensitiveSearch`).
fn lower(s: &str) -> String {
    s.to_lowercase()
}

/// Lowercase and drop diacritics (`NSCaseInsensitiveSearch | NSDiacriticInsensitiveSearch`).
fn fold(s: &str) -> String {
    s.nfd().filter(|c| !is_combining_mark(*c)).flat_map(char::to_lowercase).collect()
}

/// `-isEqualIgnoringCase:`
pub fn eq_ci(a: &str, b: &str) -> bool {
    lower(a) == lower(b)
}

/// `-hasIPrefix:`: anchored, case- and diacritic-insensitive. An empty prefix never matches.
pub fn has_iprefix(s: &str, prefix: &str) -> bool {
    !prefix.is_empty() && fold(s).starts_with(&fold(prefix))
}

/// `-containsStringIgnoringCase:`. An empty needle never matches.
pub fn contains_ci(s: &str, needle: &str) -> bool {
    !needle.is_empty() && lower(s).contains(&lower(needle))
}

/// `-normalizedString`: trim whitespace, then trim `.` characters.
pub fn normalized(s: &str) -> String {
    s.trim().trim_matches('.').to_string()
}

/// `-isBlank`
pub fn is_blank(s: &str) -> bool {
    s.trim().is_empty()
}

/// `-stringByRemovingWhitespaces` (spaces only, like the original).
pub fn remove_spaces(s: &str) -> String {
    s.replace(' ', "")
}

/// `-stringByStrippingTrailingDigits`: regex `\s*\d+$` → "".
pub fn strip_trailing_digits(s: &str) -> String {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\s*\d+$").unwrap()).replace(s, "").into_owned()
}

/// Number of UTF-16 code units, which is what `-[NSString length]` returns.
/// All the original length guards (≥4, ≥8 …) are in these units.
pub fn ns_len(s: &str) -> usize {
    s.encode_utf16().count()
}

/// File name without its last extension (`-stringByDeletingPathExtension`).
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
    fn normalization_matches_foundation() {
        assert_eq!(normalized("  ..Foo Bar.. "), "Foo Bar");
        assert_eq!(strip_trailing_digits("Photoshop 2024"), "Photoshop");
        assert_eq!(remove_spaces("Foo Bar Baz"), "FooBarBaz");
        assert_eq!(stem("com.foo.plist"), "com.foo");
        assert_eq!(stem(".hidden"), ".hidden");
    }
}
