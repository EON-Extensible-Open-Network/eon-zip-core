// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 EON contributors
//
// Additional permission under GNU GPL version 3 section 7:
// see LICENSE-EXCEPTION.md (EON Module ABI Exception 1.0).

//! Where an entry may be written, decided in one place.
//!
//! Both 7-Zip and WinRAR have shipped archives that write outside the folder a
//! person chose (WinRAR CVE-2025-8088, 7-Zip CVE-2025-11001). Every name in
//! every format passes through [`entry_path`] before anything is written, and
//! the answer is either a relative path that stays inside the target or a
//! refusal with its reason. There is no option that turns this off.

use std::path::PathBuf;

/// Why an entry is not written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Refusal {
    /// An absolute path, a drive letter or a network path (`/etc`, `C:\`, `\\server`).
    Absolute,
    /// A `..` that climbs out of the target.
    Climbs,
    /// Nothing is left of the name once `.` and separators are removed.
    Empty,
    /// A symbolic or hard link: not created (parity.md, links planned).
    Link,
}

/// What is worth saying about an entry before it is written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Warning {
    /// A program or script: it runs when opened.
    Program,
    /// A program dressed as a document (`invoice.pdf.exe`).
    DoubleExtension,
    /// Invisible characters that reverse how the name reads (`exe.pdf` shown
    /// for `fdp.exe`); they are replaced when the file is written.
    HiddenDirection,
}

/// Extensions that run code when opened, on any of the three systems.
const PROGRAMS: &[&str] = &[
    "exe",
    "com",
    "scr",
    "pif",
    "bat",
    "cmd",
    "ps1",
    "psm1",
    "vbs",
    "vbe",
    "js",
    "jse",
    "wsf",
    "wsh",
    "msi",
    "msp",
    "msix",
    "appx",
    "lnk",
    "hta",
    "cpl",
    "jar",
    "reg",
    "dll",
    "sys",
    "scf",
    "url",
    "inf",
    "application",
    "gadget",
    "sh",
    "bash",
    "zsh",
    "command",
    "app",
    "appimage",
    "run",
    "deb",
    "rpm",
    "pkg",
    "dmg",
    "apk",
    "xll",
    "iso",
    "img",
    "vhd",
    "vhdx",
    "chm",
];

/// Extensions people trust, which a program may pretend to be.
const DOCUMENTS: &[&str] = &[
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "ods", "txt", "rtf", "csv", "jpg",
    "jpeg", "png", "gif", "bmp", "webp", "mp3", "mp4", "mov", "avi", "mkv", "wav", "zip", "rar",
    "7z", "html", "htm",
];

/// Characters that reorder text on screen without being seen.
fn hides_direction(c: char) -> bool {
    matches!(c, '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

/// Names Windows reserves for devices, with or without an extension.
fn reserved(stem: &str) -> bool {
    let s = stem.to_ascii_uppercase();
    matches!(
        s.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) || ((s.starts_with("COM") || s.starts_with("LPT"))
        && s.len() == 4
        && s.as_bytes()[3].is_ascii_digit()
        && s.as_bytes()[3] != b'0')
}

/// One component made writable on every system: characters Windows refuses are
/// replaced, trailing dots and spaces (which Windows drops, and which have been
/// used to smuggle `..`) are removed, device names are prefixed.
fn clean_component(raw: &str) -> String {
    let replaced: String = raw
        .chars()
        .map(|c| {
            if c.is_control()
                || matches!(c, '<' | '>' | ':' | '"' | '|' | '?' | '*')
                || hides_direction(c)
            {
                '_'
            } else {
                c
            }
        })
        .collect();
    let trimmed = replaced.trim_end_matches(['.', ' ']).to_owned();
    let stem = trimmed.split('.').next().unwrap_or_default();
    if reserved(stem) {
        format!("_{trimmed}")
    } else {
        trimmed
    }
}

/// The relative path an entry is written to, or why it is not written.
/// Both `/` and `\` separate folders, whatever system the archive came from.
pub fn entry_path(name: &str) -> Result<PathBuf, Refusal> {
    let name = name.replace('\\', "/");
    if name.starts_with('/') {
        return Err(Refusal::Absolute);
    }
    let bytes = name.as_bytes();
    // `C:...`, which Windows reads as a drive even without a separator after it.
    if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
        return Err(Refusal::Absolute);
    }
    let mut out = PathBuf::new();
    for raw in name.split('/') {
        // Windows drops trailing dots and spaces, so `.. ` and `...` are checked
        // after the same trimming it would do.
        let looks = raw.trim_end_matches([' ']);
        if looks.is_empty() || looks == "." {
            continue;
        }
        if looks.trim_end_matches('.').is_empty() && looks.len() >= 2 {
            return Err(Refusal::Climbs);
        }
        let part = clean_component(raw);
        if part.is_empty() {
            continue;
        }
        out.push(part);
    }
    if out.as_os_str().is_empty() {
        Err(Refusal::Empty)
    } else {
        Ok(out)
    }
}

/// What to tell a person about a name before writing it.
pub fn warnings(name: &str) -> Vec<Warning> {
    let mut out = Vec::new();
    if name.chars().any(hides_direction) {
        out.push(Warning::HiddenDirection);
    }
    let file = name
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(name)
        .to_ascii_lowercase();
    let mut parts = file.rsplit('.');
    let last = parts.next().unwrap_or_default();
    let before = parts.next();
    if file.contains('.') && PROGRAMS.contains(&last) {
        out.push(Warning::Program);
        if before.is_some_and(|b| DOCUMENTS.contains(&b)) {
            out.push(Warning::DoubleExtension);
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn every_way_out_is_refused() {
        for name in [
            "/etc/passwd",
            "\\Windows\\System32\\x.dll",
            "C:\\Users\\Public\\x.exe",
            "c:x.exe",
            "\\\\server\\share\\x",
            "//server/share/x",
        ] {
            assert_eq!(entry_path(name), Err(Refusal::Absolute), "{name}");
        }
        for name in [
            "../x",
            "a/../../x",
            "a\\..\\..\\x",
            // CVE-2025-8088's family: Startup folder reached by climbing.
            "..\\..\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\x.lnk",
            // Windows drops trailing dots and spaces.
            ".. /x",
            "... /x",
            "a/.../x",
        ] {
            assert_eq!(entry_path(name), Err(Refusal::Climbs), "{name}");
        }
        assert_eq!(entry_path("./"), Err(Refusal::Empty));
        assert_eq!(entry_path(""), Err(Refusal::Empty));
    }

    #[test]
    fn ordinary_names_stay_as_they_are() {
        assert_eq!(
            entry_path("a/b/c.txt").unwrap(),
            Path::new("a").join("b").join("c.txt")
        );
        assert_eq!(
            entry_path("a\\b.txt").unwrap(),
            Path::new("a").join("b.txt")
        );
        assert_eq!(
            entry_path("./a//b.txt").unwrap(),
            Path::new("a").join("b.txt")
        );
        assert_eq!(
            entry_path("Belgeler/şirket ğüöç.docx").unwrap(),
            Path::new("Belgeler").join("şirket ğüöç.docx")
        );
        assert_eq!(entry_path("v1..2/x").unwrap(), Path::new("v1..2").join("x"));
        assert_eq!(entry_path(".hidden").unwrap(), Path::new(".hidden"));
    }

    #[test]
    fn names_windows_cannot_hold_are_made_safe() {
        // `a:b.txt` is drive A: to Windows, so it is refused above; a colon
        // later in a name would make an alternate data stream instead.
        assert_eq!(entry_path("a:b.txt"), Err(Refusal::Absolute));
        assert_eq!(entry_path("ab:c.txt").unwrap(), Path::new("ab_c.txt"));
        assert_eq!(entry_path("x?.txt").unwrap(), Path::new("x_.txt"));
        assert_eq!(entry_path("CON").unwrap(), Path::new("_CON"));
        assert_eq!(
            entry_path("dir/nul.txt").unwrap(),
            Path::new("dir").join("_nul.txt")
        );
        assert_eq!(entry_path("COM1.log").unwrap(), Path::new("_COM1.log"));
        assert_eq!(entry_path("COM10.log").unwrap(), Path::new("COM10.log"));
        assert_eq!(entry_path("evil.exe. . ").unwrap(), Path::new("evil.exe"));
        assert_eq!(
            entry_path("fdp\u{202E}exe.pdf").unwrap(),
            Path::new("fdp_exe.pdf")
        );
    }

    #[test]
    fn programs_and_disguises_are_named() {
        assert_eq!(warnings("setup.exe"), vec![Warning::Program]);
        assert_eq!(
            warnings("fatura.pdf.exe"),
            vec![Warning::Program, Warning::DoubleExtension]
        );
        assert_eq!(
            warnings("x/Rapor.DOCX.scr"),
            vec![Warning::Program, Warning::DoubleExtension]
        );
        assert_eq!(
            warnings("fdp\u{202E}exe.pdf"),
            vec![Warning::HiddenDirection]
        );
        assert!(warnings("notes.txt").is_empty());
        assert!(warnings("exe").is_empty());
    }
}
