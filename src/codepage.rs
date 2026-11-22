// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 EON contributors
//
// Additional permission under GNU GPL version 3 section 7:
// see LICENSE-EXCEPTION.md (EON Module ABI Exception 1.0).

//! The code page of names in old archives, told from the names themselves.
//!
//! A ZIP entry without its UTF-8 flag stores its name in whatever DOS code page
//! the computer that made it used: CP857 on a Turkish Windows, CP866 on a
//! Russian one, Shift-JIS on a Japanese one. 7-Zip and WinRAR read it as CP437
//! unless told otherwise, so "Şirket Raporu" comes out as "₧irket Raporu".
//! Here every name in the archive is decoded with each candidate, the readings
//! are scored for how much they look like words, and the best one wins; the
//! person's language breaks ties.

/// A way of turning stored name bytes into text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decoder {
    Utf8,
    /// A DOS (OEM) code page.
    Oem(u16),
    /// A multi-byte or Windows code page.
    Encoding(&'static encoding_rs::Encoding),
}

impl Decoder {
    /// What the window shows: "CP857 (Turkish)".
    pub fn label(self) -> String {
        match self {
            Decoder::Utf8 => "UTF-8".into(),
            Decoder::Oem(cp) => {
                let lang = match cp {
                    437 => "English",
                    850 => "Western European",
                    852 => "Central European",
                    857 => "Turkish",
                    866 => "Cyrillic",
                    737 => "Greek",
                    862 => "Hebrew",
                    775 => "Baltic",
                    _ => "DOS",
                };
                format!("CP{cp} ({lang})")
            }
            Decoder::Encoding(e) => e.name().to_owned(),
        }
    }

    /// The text, or `None` if the bytes are not valid in this code page.
    pub fn decode(self, raw: &[u8]) -> Option<String> {
        match self {
            Decoder::Utf8 => std::str::from_utf8(raw).ok().map(str::to_owned),
            Decoder::Oem(cp) => oem_cp::code_table::DECODING_TABLE_CP_MAP
                .get(&cp)
                .and_then(|t| t.decode_string_checked(raw)),
            Decoder::Encoding(e) => {
                let (text, had_errors) = e.decode_without_bom_handling(raw);
                (!had_errors).then(|| text.into_owned())
            }
        }
    }
}

const CANDIDATES: &[Decoder] = &[
    Decoder::Oem(857),
    Decoder::Oem(866),
    Decoder::Oem(850),
    Decoder::Oem(437),
    Decoder::Oem(852),
    Decoder::Oem(737),
    Decoder::Oem(862),
    Decoder::Oem(775),
    Decoder::Encoding(encoding_rs::SHIFT_JIS),
    Decoder::Encoding(encoding_rs::GBK),
    Decoder::Encoding(encoding_rs::BIG5),
    Decoder::Encoding(encoding_rs::EUC_KR),
    Decoder::Encoding(encoding_rs::WINDOWS_1251),
    Decoder::Encoding(encoding_rs::WINDOWS_1254),
    Decoder::Encoding(encoding_rs::WINDOWS_1252),
];

/// Letters written in European languages' file names, Turkish first.
const LATIN: &str = "çğıöşüÇĞİÖŞÜâîûÂÎÛàáäãåæèéêëìíïñòóôõøùúýßÀÁÄÃÅÆÈÉÊËÌÍÏÑÒÓÔÕØÙÚÝœŒąćęłńśźżĄĆĘŁŃŚŹŻčďěňřšťůžČĎĚŇŘŠŤŮŽőűŐŰ";

#[derive(PartialEq, Eq, Clone, Copy)]
enum Script {
    Latin,
    Cyrillic,
    Greek,
    Hebrew,
    Cjk,
}

fn script(c: char) -> Option<Script> {
    if LATIN.contains(c) {
        return Some(Script::Latin);
    }
    match c {
        'А'..='я' | 'Ё' | 'ё' => Some(Script::Cyrillic),
        'Α'..='ω' => Some(Script::Greek),
        'א'..='ת' => Some(Script::Hebrew),
        '\u{3040}'..='\u{30FF}' | '\u{4E00}'..='\u{9FFF}' | '\u{AC00}'..='\u{D7AF}' => {
            Some(Script::Cjk)
        }
        _ => None,
    }
}

/// How much a reading looks like names a person wrote. `None`: not text at all.
fn score(text: &str) -> Option<i64> {
    let mut total = 0i64;
    let mut scripts: Vec<Script> = Vec::new();
    let mut prev: Option<char> = None;
    for c in text.chars() {
        if c == '\u{FFFD}' || c.is_control() {
            return None;
        }
        if c.is_ascii() {
            prev = Some(c);
            continue;
        }
        if let Some(s) = script(c) {
            total += 2;
            if !scripts.contains(&s) {
                scripts.push(s);
            }
            // A capital straight after a small non-ASCII letter: the mark of
            // bytes read in the wrong table ("ЏаЁўҐв", "žüčŹ").
            if c.is_uppercase() && prev.is_some_and(|p| !p.is_ascii() && p.is_lowercase()) {
                total -= 3;
            }
        } else {
            // Box drawing, ª º ƒ ₧ ×, rare letters: what a wrong table produces.
            total -= 4;
        }
        prev = Some(c);
    }
    let mixed = i64::try_from(scripts.len().saturating_sub(1)).unwrap_or(0);
    Some(total - mixed * 6)
}

/// The decoder for a set of stored names. `prefer` is the person's language
/// (`"tr"`, `"ru"`, `"ja"`...), used to break ties.
pub fn detect(names: &[&[u8]], prefer: Option<&str>) -> Decoder {
    let any_high = names.iter().any(|n| n.iter().any(|b| *b >= 0x80));
    if !any_high {
        return Decoder::Utf8;
    }
    if names.iter().all(|n| std::str::from_utf8(n).is_ok()) {
        return Decoder::Utf8;
    }
    let favoured: &[Decoder] = match prefer.map(|p| p.get(..2).unwrap_or(p)) {
        Some("tr") => &[
            Decoder::Oem(857),
            Decoder::Encoding(encoding_rs::WINDOWS_1254),
        ],
        Some("ru" | "uk" | "be" | "bg") => &[
            Decoder::Oem(866),
            Decoder::Encoding(encoding_rs::WINDOWS_1251),
        ],
        Some("ja") => &[Decoder::Encoding(encoding_rs::SHIFT_JIS)],
        Some("zh") => &[
            Decoder::Encoding(encoding_rs::GBK),
            Decoder::Encoding(encoding_rs::BIG5),
        ],
        Some("ko") => &[Decoder::Encoding(encoding_rs::EUC_KR)],
        Some("el") => &[Decoder::Oem(737)],
        Some("he") => &[Decoder::Oem(862)],
        Some("pl" | "cs" | "sk" | "hu" | "hr" | "sl" | "ro") => &[Decoder::Oem(852)],
        _ => &[Decoder::Oem(437), Decoder::Oem(850)],
    };
    let mut best = (i64::MIN, Decoder::Oem(437));
    for d in CANDIDATES {
        let mut total = 0i64;
        let mut ok = true;
        for n in names {
            if let Some(s) = d.decode(n).as_deref().and_then(score) {
                total += s;
            } else {
                ok = false;
                break;
            }
        }
        if !ok {
            continue;
        }
        if favoured.contains(d) {
            total += 1;
        }
        if total > best.0 {
            best = (total, *d);
        }
    }
    best.1
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn oem(cp: u16, text: &str) -> Vec<u8> {
        oem_cp::code_table::ENCODING_TABLE_CP_MAP
            .get(&cp)
            .map(|t| oem_cp::encode_string_checked(text, t).unwrap())
            .unwrap()
    }

    #[test]
    fn turkish_names_from_a_turkish_windows() {
        let names = [
            oem(857, "Şirket Raporu ğüşıöç.docx"),
            oem(857, "Belgeler/Ödeme İçin.xlsx"),
        ];
        let refs: Vec<&[u8]> = names.iter().map(Vec::as_slice).collect();
        for prefer in [Some("tr"), Some("en"), None] {
            let d = detect(&refs, prefer);
            assert_eq!(d, Decoder::Oem(857), "{prefer:?}");
            assert_eq!(d.decode(&names[0]).unwrap(), "Şirket Raporu ğüşıöç.docx");
        }
    }

    #[test]
    fn russian_and_japanese_names() {
        let ru = [oem(866, "Привет мир.txt"), oem(866, "Отчёт/Документ.pdf")];
        let refs: Vec<&[u8]> = ru.iter().map(Vec::as_slice).collect();
        assert_eq!(detect(&refs, None), Decoder::Oem(866));

        let (ja, _, _) = encoding_rs::SHIFT_JIS.encode("日本語のファイル.txt");
        let d = detect(&[&ja], Some("ja"));
        assert_eq!(d.decode(&ja).unwrap(), "日本語のファイル.txt");
    }

    #[test]
    fn utf8_and_ascii_are_left_alone() {
        assert_eq!(detect(&["şirket.txt".as_bytes()], None), Decoder::Utf8);
        assert_eq!(detect(&[b"plain.txt"], Some("tr")), Decoder::Utf8);
    }
}
