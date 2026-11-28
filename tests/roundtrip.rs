// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 EON contributors
//
// Additional permission under GNU GPL version 3 section 7:
// see LICENSE-EXCEPTION.md (EON Module ABI Exception 1.0).

//! Every format made and read back byte for byte; passwords; volumes;
//! conversion; archives built to attack; damage found by a test; and the real
//! 7-Zip reading what EON Zip makes and the other way round.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use eon_zip_core::*;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

struct Dir(PathBuf);

impl Dir {
    fn new(tag: &str) -> Dir {
        let d = std::env::temp_dir().join(format!("eon-zip-{tag}-{}", std::process::id()));
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

const WHEN: u64 = 1_700_000_000;

/// A folder with what archives meet in life: nested folders, Turkish names,
/// an empty file, an empty folder, text that compresses, a JPEG that does not.
fn fixture(root: &Path) -> PathBuf {
    let top = root.join("Proje Şirketi");
    std::fs::create_dir_all(top.join("Belgeler/Eski")).unwrap();
    std::fs::create_dir_all(top.join("boş klasör")).unwrap();
    let text = (0..4000).fold(String::new(), |mut s, i| {
        use std::fmt::Write as _;
        let _ = writeln!(s, "satır {i}: ğüşıöç ĞÜŞİÖÇ");
        s
    });
    std::fs::write(top.join("Belgeler/rapor.txt"), &text).unwrap();
    std::fs::write(top.join("Belgeler/Eski/not.md"), "# Not\n\nMerhaba.\n").unwrap();
    std::fs::write(top.join("boş.txt"), b"").unwrap();
    let noise: Vec<u8> = (0..200_000u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect();
    let mut jpg = vec![0xFF, 0xD8, 0xFF, 0xE0];
    jpg.extend_from_slice(&noise);
    std::fs::write(top.join("foto.jpg"), &jpg).unwrap();
    for f in [
        "Belgeler/rapor.txt",
        "Belgeler/Eski/not.md",
        "boş.txt",
        "foto.jpg",
    ] {
        let file = std::fs::File::options()
            .write(true)
            .open(top.join(f))
            .unwrap();
        file.set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(WHEN))
            .unwrap();
    }
    top
}

/// Every file under `dir`, relative, with its bytes.
fn contents(dir: &Path) -> Vec<(String, Vec<u8>)> {
    fn walk(base: &Path, dir: &Path, out: &mut Vec<(String, Vec<u8>)>) {
        let mut items: Vec<PathBuf> = std::fs::read_dir(dir)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .collect();
        items.sort();
        for p in items {
            let rel = p
                .strip_prefix(base)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            if p.is_dir() {
                out.push((format!("{rel}/"), Vec::new()));
                walk(base, &p, out);
            } else {
                out.push((rel, std::fs::read(&p).unwrap()));
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, dir, &mut out);
    out
}

fn settings(format: Format) -> Settings {
    Settings {
        format,
        solid: true,
        ..Settings::default()
    }
}

fn quiet(_: &Progress) {}

#[test]
fn every_format_round_trips() {
    let d = Dir::new("formats");
    let src = fixture(&d.0);
    let expected = contents(&d.0);
    for format in [
        Format::Eonz,
        Format::Zip,
        Format::SevenZ,
        Format::Tar,
        Format::TarGz,
        Format::TarBz2,
        Format::TarXz,
        Format::TarZst,
    ] {
        for solid in [true, false] {
            if !solid && format != Format::SevenZ {
                continue;
            }
            let target = d.0.join(format!("out-{solid}.{}", format.extension()));
            let s = Settings {
                solid,
                ..settings(format)
            };
            create(
                std::slice::from_ref(&src),
                &target,
                &s,
                &quiet,
                &Cancel::default(),
            )
            .unwrap();
            let a = Archive::open(&target, None, None).unwrap();
            assert_eq!(a.format, format);
            let dest = d.0.join(format!("x-{}-{solid}", format.extension()));
            let plan = a.plan(&dest, &Extract::default());
            assert!(plan.refused.is_empty(), "{format:?}: {:?}", plan.refused);
            a.extract(&plan, &quiet, &Cancel::default()).unwrap();
            // One top folder: extracted as itself, not inside another.
            let got = contents(&dest);
            let want: Vec<_> = expected
                .iter()
                .filter(|(n, _)| !n.starts_with("out-") && !n.starts_with("x-"))
                .cloned()
                .collect();
            assert_eq!(got, want, "{format:?} solid={solid}");
            let t = std::fs::metadata(dest.join("Proje Şirketi/Belgeler/rapor.txt"))
                .unwrap()
                .modified()
                .unwrap();
            assert_eq!(
                t.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs(),
                WHEN,
                "{format:?} time"
            );
            let report = a.test(&quiet, &Cancel::default()).unwrap();
            assert!(report.failed.is_empty(), "{format:?}: {:?}", report.failed);
        }
    }
}

#[test]
fn single_files_round_trip() {
    let d = Dir::new("single");
    let f = d.0.join("kayıt.log");
    let body: Vec<u8> = (0..300_000u32)
        .flat_map(|i| format!("{i}\n").into_bytes())
        .collect();
    std::fs::write(&f, &body).unwrap();
    for format in [Format::Gz, Format::Bz2, Format::Xz, Format::Zst] {
        let target = d.0.join(format!("kayıt.log.{}", format.extension()));
        create(
            std::slice::from_ref(&f),
            &target,
            &settings(format),
            &quiet,
            &Cancel::default(),
        )
        .unwrap();
        let a = Archive::open(&target, None, None).unwrap();
        assert_eq!(a.entries()[0].name, "kayıt.log", "{format:?}");
        let dest = d.0.join(format!("x-{}", format.extension()));
        let plan = a.plan(&dest, &Extract::default());
        a.extract(&plan, &quiet, &Cancel::default()).unwrap();
        assert_eq!(
            std::fs::read(dest.join("kayıt.log")).unwrap(),
            body,
            "{format:?}"
        );
    }
}

#[test]
fn passwords_and_hidden_names() {
    let d = Dir::new("password");
    let src = fixture(&d.0);
    for format in [Format::Zip, Format::SevenZ] {
        let target = d.0.join(format!("gizli.{}", format.extension()));
        let s = Settings {
            password: Some("Parola 123 ğ".into()),
            encrypt_names: true,
            ..settings(format)
        };
        create(
            std::slice::from_ref(&src),
            &target,
            &s,
            &quiet,
            &Cancel::default(),
        )
        .unwrap();
        if format == Format::SevenZ {
            // Names are encrypted too: nothing shows without the password.
            assert_eq!(
                Archive::open(&target, None, None).err(),
                Some(Error::PasswordNeeded)
            );
            assert!(matches!(
                Archive::open(&target, Some("yanlış"), None).err(),
                Some(Error::WrongPassword | Error::Format(_))
            ));
        } else {
            let a = Archive::open(&target, None, None).unwrap();
            assert!(a.encrypted());
            let plan = a.plan(&d.0.join("nopw"), &Extract::default());
            assert_eq!(
                a.extract(&plan, &quiet, &Cancel::default()).err(),
                Some(Error::PasswordNeeded)
            );
            let mut wrong = Archive::open(&target, None, None).unwrap();
            wrong.set_password(Some("yanlış"));
            let plan = wrong.plan(&d.0.join("wrongpw"), &Extract::default());
            assert_eq!(
                wrong.extract(&plan, &quiet, &Cancel::default()).err(),
                Some(Error::WrongPassword)
            );
        }
        let a = Archive::open(&target, Some("Parola 123 ğ"), None).unwrap();
        let dest = d.0.join(format!("ok-{}", format.extension()));
        let plan = a.plan(&dest, &Extract::default());
        a.extract(&plan, &quiet, &Cancel::default()).unwrap();
        assert_eq!(
            std::fs::read_to_string(dest.join("Proje Şirketi/Belgeler/Eski/not.md")).unwrap(),
            "# Not\n\nMerhaba.\n"
        );
    }
}

#[test]
fn volumes_and_conversion() {
    let d = Dir::new("volumes");
    let src = fixture(&d.0);
    let target = d.0.join("parçalı.7z");
    let s = Settings {
        split: Some(50_000),
        ..settings(Format::SevenZ)
    };
    let parts = create(&[src], &target, &s, &quiet, &Cancel::default()).unwrap();
    assert!(parts.len() >= 3, "{parts:?}");
    // Opened from any part.
    let a = Archive::open(&parts[1], None, None).unwrap();
    let zip = d.0.join("çevrildi.zip");
    convert(&a, &zip, &settings(Format::Zip), &quiet, &Cancel::default()).unwrap();
    let z = Archive::open(&zip, None, None).unwrap();
    assert!(z
        .entries()
        .iter()
        .any(|e| e.name == "Proje Şirketi/Belgeler/rapor.txt"));
    assert!(!d
        .0
        .join(format!(".eon-zip-convert-{}", std::process::id()))
        .exists());
}

#[test]
fn loose_files_get_a_folder_and_a_taken_folder_is_not_merged() {
    let d = Dir::new("smart");
    let a_txt = d.0.join("a.txt");
    let b_txt = d.0.join("b.txt");
    std::fs::write(&a_txt, "a").unwrap();
    std::fs::write(&b_txt, "b").unwrap();
    let loose = d.0.join("dağınık.zip");
    create(
        &[a_txt, b_txt],
        &loose,
        &settings(Format::Zip),
        &quiet,
        &Cancel::default(),
    )
    .unwrap();
    let dest = d.0.join("dest");
    let a = Archive::open(&loose, None, None).unwrap();
    let plan = a.plan(&dest, &Extract::default());
    assert_eq!(plan.root, dest.join("dağınık"));
    a.extract(&plan, &quiet, &Cancel::default()).unwrap();
    assert!(dest.join("dağınık/a.txt").is_file());
    // The same again: a second folder, not the first one filled twice.
    let plan = a.plan(&dest, &Extract::default());
    assert_eq!(plan.root, dest.join("dağınık (1)"));

    let src = fixture(&d.0);
    let one = d.0.join("tek.7z");
    create(
        &[src],
        &one,
        &settings(Format::SevenZ),
        &quiet,
        &Cancel::default(),
    )
    .unwrap();
    let a = Archive::open(&one, None, None).unwrap();
    let plan = a.plan(&dest, &Extract::default());
    a.extract(&plan, &quiet, &Cancel::default()).unwrap();
    let plan = a.plan(&dest, &Extract::default());
    a.extract(&plan, &quiet, &Cancel::default()).unwrap();
    assert!(dest.join("Proje Şirketi (1)/Belgeler/rapor.txt").is_file());
}

/// A ZIP written by hand, the way an attacker would, with names no tool makes.
fn hostile_zip(path: &Path, entries: &[(&str, &[u8])], symlink: Option<(&str, &str)>) {
    let mut z = zip::ZipWriter::new(std::fs::File::create(path).unwrap());
    let o = zip::write::SimpleFileOptions::default();
    for (name, body) in entries {
        z.start_file(*name, o).unwrap();
        z.write_all(body).unwrap();
    }
    if let Some((name, to)) = symlink {
        z.add_symlink(name, to, o).unwrap();
    }
    z.finish().unwrap();
}

#[test]
fn archives_built_to_attack_write_nothing_outside() {
    let d = Dir::new("hostile");
    let evil = d.0.join("evil.zip");
    hostile_zip(
        &evil,
        &[
            ("../kaçtı.txt", b"x"),
            ("ok/../../kaçtı2.txt", b"x"),
            ("/etc/kaçtı3.txt", b"x"),
            ("C:/Windows/kaçtı4.txt", b"x"),
            ("..\\..\\kaçtı5.txt", b"x"),
            ("güvenli/fatura.pdf.exe", b"MZ"),
            ("güvenli/belge.txt", b"ok"),
        ],
        Some(("güvenli/bağ", "../../..")),
    );
    let dest = d.0.join("dest");
    let a = Archive::open(&evil, None, None).unwrap();
    let plan = a.plan(&dest, &Extract::default());
    assert_eq!(plan.refused.len(), 6, "{:?}", plan.refused);
    assert!(plan
        .warnings
        .iter()
        .any(|(_, w)| *w == safe::Warning::DoubleExtension));
    a.extract(&plan, &quiet, &Cancel::default()).unwrap();
    for escaped in ["kaçtı.txt", "kaçtı2.txt", "kaçtı5.txt"] {
        assert!(!d.0.join(escaped).exists(), "{escaped}");
    }
    assert!(dest.join("güvenli/belge.txt").is_file());
    assert!(!dest.join("güvenli/bağ").exists());
}

#[test]
fn bombs_stop_and_lies_are_caught() {
    let d = Dir::new("bomb");
    let big = d.0.join("sıfır.bin");
    std::fs::write(&big, vec![0u8; 5 << 20]).unwrap();
    let zip = d.0.join("bomba.zip");
    create(
        &[big],
        &zip,
        &settings(Format::Zip),
        &quiet,
        &Cancel::default(),
    )
    .unwrap();
    let a = Archive::open(&zip, None, None).unwrap();
    let plan = a.plan(
        &d.0.join("dest"),
        &Extract {
            limit: 1 << 20,
            ..Extract::default()
        },
    );
    assert!(plan.over_limit);
    assert!(matches!(
        a.extract(&plan, &quiet, &Cancel::default()),
        Err(Error::TooLarge { .. })
    ));
    let plan = a.plan(
        &d.0.join("dest"),
        &Extract {
            limit: 1 << 20,
            allow_large: true,
            ..Extract::default()
        },
    );
    a.extract(&plan, &quiet, &Cancel::default()).unwrap();
}

#[test]
fn damage_is_found_by_a_test() {
    let d = Dir::new("damage");
    let src = fixture(&d.0);
    for format in [Format::Zip, Format::SevenZ] {
        let target = d.0.join(format!("bozuk.{}", format.extension()));
        let s = Settings {
            level: Level::Store,
            ..settings(format)
        };
        create(
            std::slice::from_ref(&src),
            &target,
            &s,
            &quiet,
            &Cancel::default(),
        )
        .unwrap();
        let mut bytes = std::fs::read(&target).unwrap();
        // Inside the stored text of rapor.txt.
        let needle = "satır 200".as_bytes();
        let at = bytes
            .windows(needle.len())
            .position(|w| w == needle)
            .unwrap();
        bytes[at + 3] ^= 0x55;
        std::fs::write(&target, bytes).unwrap();
        let a = Archive::open(&target, None, None).unwrap();
        let report = a.test(&quiet, &Cancel::default()).unwrap();
        assert!(
            !report.failed.is_empty(),
            "{format:?} damage went unnoticed"
        );
    }
}

#[test]
fn cancel_leaves_nothing_behind() {
    let d = Dir::new("cancel");
    let src = fixture(&d.0);
    let target = d.0.join("yarım.7z");
    let cancel = Cancel::default();
    cancel.stop();
    assert_eq!(
        create(&[src], &target, &settings(Format::SevenZ), &quiet, &cancel).err(),
        Some(Error::Cancelled)
    );
    assert!(!target.exists());
    let leftovers: Vec<_> = std::fs::read_dir(&d.0)
        .unwrap()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().contains("partial"))
        .collect();
    assert!(leftovers.is_empty());
}

#[cfg(windows)]
#[test]
fn the_internet_mark_follows_the_files() {
    let d = Dir::new("motw");
    let src = fixture(&d.0);
    let target = d.0.join("indirildi.zip");
    create(
        &[src],
        &target,
        &settings(Format::Zip),
        &quiet,
        &Cancel::default(),
    )
    .unwrap();
    let mark = b"[ZoneTransfer]\r\nZoneId=3\r\n";
    std::fs::write(format!("{}:Zone.Identifier", target.display()), mark).unwrap();
    let a = Archive::open(&target, None, None).unwrap();
    let dest = d.0.join("dest");
    a.extract(
        &a.plan(&dest, &Extract::default()),
        &quiet,
        &Cancel::default(),
    )
    .unwrap();
    let got = std::fs::read(format!(
        "{}:Zone.Identifier",
        dest.join("Proje Şirketi/foto.jpg").display()
    ))
    .unwrap();
    assert_eq!(got, mark);
}

/// The real 7-Zip, when it is on this machine (CI installs it).
fn seven_zip() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("EON_ZIP_7Z") {
        return Some(PathBuf::from(p));
    }
    [
        r"C:\Program Files\7-Zip\7z.exe",
        "/usr/bin/7z",
        "/usr/bin/7zz",
        "/opt/homebrew/bin/7zz",
        "/usr/local/bin/7zz",
    ]
    .iter()
    .map(PathBuf::from)
    .find(|p| p.is_file())
}

#[test]
fn the_real_7zip_agrees() {
    let Some(sz) = seven_zip() else {
        eprintln!("7-Zip is not on this machine; skipped");
        return;
    };
    let d = Dir::new("interop");
    let src = fixture(&d.0);
    // What EON Zip makes, 7-Zip tests.
    for (format, password) in [
        (Format::SevenZ, None),
        (Format::SevenZ, Some("pw ğ")), // 7-Zip refuses non-ASCII ZIP passwords outright (portable_zip_password).
        (Format::Zip, Some("pw g 123")),
        (Format::TarXz, None),
    ] {
        let target =
            d.0.join(format!("eon-{}.{}", password.is_some(), format.extension()));
        let s = Settings {
            password: password.map(str::to_owned),
            ..settings(format)
        };
        create(
            std::slice::from_ref(&src),
            &target,
            &s,
            &quiet,
            &Cancel::default(),
        )
        .unwrap();
        let mut cmd = std::process::Command::new(&sz);
        cmd.arg("t").arg(&target);
        if let Some(p) = password {
            cmd.arg(format!("-p{p}"));
        }
        let out = cmd.output().unwrap();
        assert!(
            out.status.success(),
            "7-Zip refused {format:?}: {}",
            String::from_utf8_lossy(&out.stdout)
        );
    }
    // What 7-Zip makes, EON Zip reads.
    for (ext, extra) in [
        ("7z", vec!["-mx=9", "-ms=on"]),
        ("zip", vec!["-mm=Deflate64"]),
        ("zip", vec!["-mem=AES256", "-pgizli"]),
    ] {
        let target = d.0.join(format!("7zip-{}.{ext}", extra.len()));
        let out = std::process::Command::new(&sz)
            .arg("a")
            .args(&extra)
            .arg(&target)
            .arg(&src)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stdout)
        );
        let password = extra.iter().find_map(|a| a.strip_prefix("-p"));
        let a = Archive::open(&target, password, None).unwrap();
        let dest = d.0.join(format!("x-{ext}-{}", extra.len()));
        a.extract(
            &a.plan(&dest, &Extract::default()),
            &quiet,
            &Cancel::default(),
        )
        .unwrap();
        assert_eq!(
            std::fs::read(dest.join("Proje Şirketi/Belgeler/rapor.txt")).unwrap(),
            std::fs::read(src.join("Belgeler/rapor.txt")).unwrap(),
            "{ext} {extra:?}"
        );
    }
}
