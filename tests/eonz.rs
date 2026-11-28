// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 EON contributors
//
// Additional permission under GNU GPL version 3 section 7:
// see LICENSE-EXCEPTION.md (EON Module ABI Exception 1.0).

//! `.eonz`, EON Zip's own format (madde 49i): what it promises beyond the other formats —
//! repeated content stored once, names hidden by the password, damage found and repaired
//! from the recovery data inside the archive.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use eon_zip_core::*;
use std::path::{Path, PathBuf};

struct Dir(PathBuf);

impl Dir {
    fn new(tag: &str) -> Dir {
        let d = std::env::temp_dir().join(format!("eon-zip-eonz-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        Dir(d)
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn quiet(_: &Progress) {}

/// Bytes that do not compress (so sizes show deduplication, not compression).
fn noise(n: usize, seed: u64) -> Vec<u8> {
    let mut s = seed | 1;
    (0..n)
        .map(|_| {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            (s >> 24) as u8
        })
        .collect()
}

fn make(src: &Path, target: &Path, password: Option<&str>, recovery: u8) {
    let s = Settings {
        format: Format::Eonz,
        level: Level::Fast,
        password: password.map(str::to_owned),
        recovery_percent: recovery,
        ..Settings::default()
    };
    create(
        std::slice::from_ref(&src.to_path_buf()),
        target,
        &s,
        &quiet,
        &Cancel::default(),
    )
    .unwrap();
}

fn extract_all(archive: &Path, password: Option<&str>, dest: &Path) -> Report {
    let a = Archive::open(archive, password, None).unwrap();
    assert_eq!(a.format, Format::Eonz);
    let plan = a.plan(dest, &Extract::default());
    assert!(plan.refused.is_empty(), "{:?}", plan.refused);
    a.extract(&plan, &quiet, &Cancel::default()).unwrap()
}

#[test]
fn repeated_content_is_stored_once() {
    let d = Dir::new("dedup");
    let src = d.0.join("veri");
    std::fs::create_dir_all(src.join("kopya")).unwrap();
    let big = noise(3 * 1024 * 1024, 7);
    std::fs::write(src.join("bir.bin"), &big).unwrap();
    std::fs::write(src.join("kopya/iki.bin"), &big).unwrap();
    // The same content with a few bytes put in at the front: content-defined chunks find
    // almost all of it again.
    let mut shifted = b"EON".to_vec();
    shifted.extend_from_slice(&big);
    std::fs::write(src.join("kaymış.bin"), &shifted).unwrap();
    let target = d.0.join("veri.eonz");
    make(&src, &target, None, 0);
    let size = std::fs::metadata(&target).unwrap().len();
    // 9 MiB of files, 3 MiB of distinct content that does not compress.
    assert!(
        size < big.len() as u64 + 600 * 1024,
        "archive is {size} bytes"
    );
    let dest = d.0.join("çıkan");
    let r = extract_all(&target, None, &dest);
    assert_eq!(r.files, 3);
    assert_eq!(std::fs::read(dest.join("veri/kopya/iki.bin")).unwrap(), big);
    assert_eq!(
        std::fs::read(dest.join("veri/kaymış.bin")).unwrap(),
        shifted
    );
}

#[test]
fn a_password_hides_names_and_contents() {
    let d = Dir::new("password");
    let src = d.0.join("gizli");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("banka-şifreleri.txt"), "hesap: 1234\n".repeat(500)).unwrap();
    let target = d.0.join("gizli.eonz");
    make(&src, &target, Some("doğru parola"), 5);
    let raw = std::fs::read(&target).unwrap();
    let find = |needle: &[u8]| raw.windows(needle.len()).any(|w| w == needle);
    assert!(!find("banka-şifreleri".as_bytes()) && !find(b"hesap: 1234"));
    assert_eq!(
        Archive::open(&target, None, None).err(),
        Some(Error::PasswordNeeded)
    );
    assert_eq!(
        Archive::open(&target, Some("yanlış"), None).err(),
        Some(Error::WrongPassword)
    );
    let dest = d.0.join("açık");
    extract_all(&target, Some("doğru parola"), &dest);
    assert_eq!(
        std::fs::read_to_string(dest.join("gizli/banka-şifreleri.txt")).unwrap(),
        "hesap: 1234\n".repeat(500)
    );
}

fn damage(path: &Path, at: u64, len: usize) {
    let mut b = std::fs::read(path).unwrap();
    for x in &mut b[at as usize..at as usize + len] {
        *x ^= 0x5A;
    }
    std::fs::write(path, b).unwrap();
}

#[test]
fn damage_is_found_and_repaired_from_the_recovery_data() {
    let d = Dir::new("repair");
    let src = d.0.join("arşiv");
    std::fs::create_dir_all(&src).unwrap();
    let a = noise(2 * 1024 * 1024, 3);
    let text = "satır ğüşıöç\n".repeat(80_000);
    std::fs::write(src.join("a.bin"), &a).unwrap();
    std::fs::write(src.join("metin.txt"), &text).unwrap();
    let target = d.0.join("arşiv.eonz");
    make(&src, &target, Some("parola"), 10);

    // A burst in the data, as a bad sector would make.
    let broken = d.0.join("bozuk.eonz");
    std::fs::copy(&target, &broken).unwrap();
    damage(&broken, 300_000, 20_000);
    let opened = Archive::open(&broken, Some("parola"), None).unwrap();
    let report = opened.test(&quiet, &Cancel::default()).unwrap();
    assert!(!report.failed.is_empty(), "the damage was not noticed");

    let fixed = d.0.join("onarılmış.eonz");
    let r = eonz::repair(&broken, &fixed, &Cancel::default()).unwrap();
    assert!(r.damaged > 0 && r.whole, "{r:?}");
    assert_eq!(
        std::fs::read(&fixed).unwrap(),
        std::fs::read(&target).unwrap()
    );
    let dest = d.0.join("çıkan");
    extract_all(&fixed, Some("parola"), &dest);
    assert_eq!(std::fs::read(dest.join("arşiv/a.bin")).unwrap(), a);
    assert_eq!(
        std::fs::read_to_string(dest.join("arşiv/metin.txt")).unwrap(),
        text
    );

    // The header itself, and with it where everything is.
    let headless = d.0.join("başsız.eonz");
    std::fs::copy(&target, &headless).unwrap();
    damage(&headless, 0, 128);
    assert!(matches!(
        Archive::open(&headless, Some("parola"), None).err(),
        Some(Error::Damaged(_))
    ));
    let fixed2 = d.0.join("onarılmış2.eonz");
    let r = eonz::repair(&headless, &fixed2, &Cancel::default()).unwrap();
    assert!(r.whole, "{r:?}");
    assert_eq!(
        std::fs::read(&fixed2).unwrap(),
        std::fs::read(&target).unwrap()
    );

    // An archive with nothing wrong needs no repair and gets no copy.
    let none = d.0.join("gereksiz.eonz");
    let r = eonz::repair(&target, &none, &Cancel::default()).unwrap();
    assert!(r.whole && r.damaged == 0 && !none.exists());
}

#[test]
fn too_much_damage_is_reported_not_hidden() {
    let d = Dir::new("toomuch");
    let src = d.0.join("x");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("a.bin"), noise(1024 * 1024, 9)).unwrap();
    let target = d.0.join("x.eonz");
    make(&src, &target, None, 1);
    // Far more than 1 % of the archive.
    damage(&target, 1000, 400_000);
    let out = d.0.join("y.eonz");
    let r = eonz::repair(&target, &out, &Cancel::default()).unwrap();
    assert!(r.damaged > 0 && !r.whole, "{r:?}");
}
