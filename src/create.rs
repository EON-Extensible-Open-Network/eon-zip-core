// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 EON contributors
//
// Additional permission under GNU GPL version 3 section 7:
// see LICENSE-EXCEPTION.md (EON Module ABI Exception 1.0).

//! Making archives: ZIP, 7z, the tar family and single compressed files, split
//! into volumes when asked, and converting one archive into another format.

use crate::format::Format;
use crate::read::{Archive, Extract};
use crate::{time, volume, Cancel, Counting, Error, OnProgress, Progress, Result};
use serde::{Deserialize, Serialize};
use std::cell::Cell;
use std::fs::File;
use std::io::{self, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

/// How hard to compress, the same six steps 7-Zip offers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Store,
    Fastest,
    Fast,
    #[default]
    Normal,
    Maximum,
    Ultra,
}

impl Level {
    /// 0–9 on the LZMA / xz / deflate scale.
    fn nine(self) -> u32 {
        match self {
            Level::Store => 0,
            Level::Fastest => 1,
            Level::Fast => 3,
            Level::Normal => 5,
            Level::Maximum => 7,
            Level::Ultra => 9,
        }
    }

    /// 1–22 on Zstandard's scale.
    fn zstd(self) -> i32 {
        match self {
            Level::Store | Level::Fastest => 1,
            Level::Fast => 3,
            Level::Normal => 9,
            Level::Maximum => 17,
            Level::Ultra => 22,
        }
    }
}

/// The compression method. `None` in [`Settings`] picks the format's best.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Method {
    Lzma2,
    Deflate,
    Bzip2,
    Zstd,
    Xz,
    Ppmd,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub format: Format,
    pub level: Level,
    pub method: Option<Method>,
    pub password: Option<String>,
    /// 7z: encrypt the list of names too, so it shows nothing without the password.
    pub encrypt_names: bool,
    /// 7z: compress files together in one stream.
    pub solid: bool,
    /// Cut the archive into parts of this many bytes.
    pub split: Option<u64>,
    /// ZIP: a comment stored in the archive.
    pub comment: Option<String>,
    /// Files that are already compressed (JPEG, MP4, ZIP...) are stored as
    /// they are instead of compressed again for nothing.
    pub store_compressed: bool,
    /// Threads for LZMA2 and Zstandard; 0 means every core.
    pub threads: u32,
    /// `.eonz`: recovery data, as a share of the archive (0–100; 0 is none).
    pub recovery_percent: u8,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            format: Format::SevenZ,
            level: Level::Normal,
            method: None,
            password: None,
            encrypt_names: true,
            solid: true,
            split: None,
            comment: None,
            store_compressed: true,
            threads: 0,
            recovery_percent: 5,
        }
    }
}

/// Whether other programs can open a ZIP with this password. The ZIP standard
/// does not say how a password becomes bytes: EON Zip uses UTF-8, and 7-Zip
/// refuses any ZIP password with a letter outside ASCII ("Parameter is
/// incorrect"). 7z has no such problem (its passwords are UTF-16), so the
/// window suggests 7z, or English letters and digits, when this is false.
pub fn portable_zip_password(password: &str) -> bool {
    password.is_ascii()
}

/// Extensions whose content is already compressed.
const COMPRESSED: &[&str] = &[
    "jpg", "jpeg", "png", "gif", "webp", "avif", "heic", "heif", "jxl", "mp4", "m4v", "mkv",
    "webm", "mov", "avi", "wmv", "mp3", "m4a", "aac", "ogg", "opus", "flac", "wma", "zip", "7z",
    "rar", "gz", "tgz", "bz2", "xz", "txz", "zst", "lz4", "br", "cab", "jar", "apk", "aab", "docx",
    "xlsx", "pptx", "odt", "ods", "odp", "epub", "woff", "woff2", "msi", "dmg",
];

fn already_compressed(path: &Path) -> bool {
    path.extension()
        .map(|e| e.to_string_lossy().to_ascii_lowercase())
        .is_some_and(|e| COMPRESSED.contains(&e.as_str()))
}

/// A file or folder to add, and its name inside the archive.
pub(crate) struct Source {
    pub(crate) path: PathBuf,
    pub(crate) name: String,
    pub(crate) is_dir: bool,
    pub(crate) size: u64,
}

/// Everything under `sources`, named as it will be stored: a folder keeps its
/// own name at the top, a file its file name. Links are not followed.
fn collect(sources: &[PathBuf]) -> Result<Vec<Source>> {
    fn walk(path: &Path, name: &str, out: &mut Vec<Source>) -> Result<()> {
        let meta = std::fs::symlink_metadata(path)
            .map_err(|e| Error::Io(format!("{}: {e}", path.display())))?;
        if meta.is_dir() {
            out.push(Source {
                path: path.to_path_buf(),
                name: name.to_owned(),
                is_dir: true,
                size: 0,
            });
            let mut children: Vec<PathBuf> = std::fs::read_dir(path)
                .map_err(|e| Error::Io(e.to_string()))?
                .flatten()
                .map(|e| e.path())
                .collect();
            children.sort();
            for c in children {
                let child = c
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                walk(&c, &format!("{name}/{child}"), out)?;
            }
        } else if meta.is_file() {
            out.push(Source {
                path: path.to_path_buf(),
                name: name.to_owned(),
                is_dir: false,
                size: meta.len(),
            });
        }
        Ok(())
    }
    let mut out = Vec::new();
    for s in sources {
        let name = s
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .ok_or_else(|| Error::Io(format!("{} has no name", s.display())))?;
        walk(s, &name, &mut out)?;
    }
    Ok(out)
}

fn threads(s: &Settings) -> u32 {
    if s.threads > 0 {
        s.threads
    } else {
        std::thread::available_parallelism().map_or(1, |n| u32::try_from(n.get()).unwrap_or(1))
    }
}

fn io_err(e: impl std::fmt::Display) -> Error {
    Error::Io(e.to_string())
}

/// Create `target` from `sources`. The archive is written under a working name
/// and renamed when whole; on failure or cancel nothing is left behind.
/// Returns the file, or the parts when split.
pub fn create(
    sources: &[PathBuf],
    target: &Path,
    s: &Settings,
    progress: OnProgress<'_>,
    cancel: &Cancel,
) -> Result<Vec<PathBuf>> {
    if !s.format.creatable() {
        return Err(Error::Unsupported(format!(
            "{} archives cannot be created",
            s.format.name()
        )));
    }
    let items = collect(sources)?;
    if s.format.single() && (items.len() != 1 || items[0].is_dir) {
        return Err(Error::Unsupported(format!(
            "{} holds one file; use TAR.{} for several",
            s.format.name(),
            s.format.name()
        )));
    }
    let working = target.with_file_name(format!(
        ".{}.eon-zip-partial",
        target
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default()
    ));
    let total: u64 = items.iter().map(|i| i.size).sum();
    let done = Cell::new(0u64);
    let outcome = (|| -> Result<()> {
        // `.eonz` reads back what it wrote, to compute its recovery data.
        let file = if s.format == Format::Eonz {
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .open(&working)
        } else {
            File::create(&working)
        }
        .map_err(io_err)?;
        match s.format {
            Format::Eonz => {
                crate::eonz::write(file, &items, s, threads(s), &done, total, progress, cancel)
            }
            Format::Zip => write_zip(file, &items, s, &done, total, progress, cancel),
            Format::SevenZ => write_7z(file, &items, s, &done, total, progress, cancel),
            Format::Tar | Format::TarGz | Format::TarBz2 | Format::TarXz | Format::TarZst => {
                write_tar(file, &items, s, &done, total, progress, cancel)
            }
            _ => write_single(file, &items[0], s, &done, total, progress, cancel),
        }
    })();
    if let Err(e) = outcome {
        let _ = std::fs::remove_file(&working);
        return Err(e);
    }
    std::fs::rename(&working, target).map_err(io_err)?;
    progress(&Progress {
        done: total,
        total,
        name: String::new(),
    });
    match s.split {
        Some(size) if size > 0 => volume::split(target, size).map_err(io_err),
        _ => Ok(vec![target.to_path_buf()]),
    }
}

fn reader<'a>(
    item: &'a Source,
    done: &'a Cell<u64>,
    total: u64,
    progress: OnProgress<'a>,
    cancel: &'a Cancel,
) -> Result<Counting<'a, File>> {
    Ok(Counting {
        inner: File::open(&item.path)
            .map_err(|e| Error::Io(format!("{}: {e}", item.path.display())))?,
        done,
        total,
        name: &item.name,
        progress,
        cancel,
        last: Cell::new(done.get()),
    })
}

fn modified(path: &Path) -> Option<std::time::SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

#[allow(clippy::too_many_arguments, clippy::many_single_char_names)]
fn write_zip(
    file: File,
    items: &[Source],
    s: &Settings,
    done: &Cell<u64>,
    total: u64,
    progress: OnProgress<'_>,
    cancel: &Cancel,
) -> Result<()> {
    use zip::write::{FullFileOptions, ZipWriter};
    use zip::CompressionMethod as M;
    let mut z = ZipWriter::new(BufWriter::new(file));
    let method = match (s.level, s.method) {
        (Level::Store, _) => M::Stored,
        (_, Some(Method::Bzip2)) => M::Bzip2,
        (_, Some(Method::Zstd)) => M::Zstd,
        (_, Some(Method::Xz | Method::Lzma2)) => M::Xz,
        (_, Some(Method::Ppmd)) => M::Ppmd,
        _ => M::Deflated,
    };
    let level = match method {
        M::Zstd => Some(i64::from(s.level.zstd())),
        M::Stored => None,
        _ => Some(i64::from(s.level.nine().max(1))),
    };
    for item in items {
        let mut o: FullFileOptions<'_, '_> = FullFileOptions::default();
        let t = modified(&item.path);
        if let Some(t) = t {
            let (y, mo, d, h, mi, se) = time::to_fields(t);
            if let Ok(dt) = zip::DateTime::from_date_and_time(
                u16::try_from(y.clamp(1980, 2107)).unwrap_or(1980),
                mo as u8,
                d as u8,
                h as u8,
                mi as u8,
                se as u8,
            ) {
                o = o.last_modified_time(dt);
            }
            // The exact time in UTC, as Info-ZIP's extended timestamp.
            if let Some(secs) = t
                .duration_since(std::time::UNIX_EPOCH)
                .ok()
                .and_then(|d| u32::try_from(d.as_secs()).ok())
            {
                let mut data = vec![1u8];
                data.extend_from_slice(&secs.to_le_bytes());
                let _ = o.add_extra_field(0x5455, data, false);
            }
        }
        #[cfg(unix)]
        if let Ok(meta) = std::fs::metadata(&item.path) {
            use std::os::unix::fs::PermissionsExt;
            o = o.unix_permissions(meta.permissions().mode() & 0o777);
        }
        if let Some(pw) = s.password.as_deref() {
            o = o.with_aes_encryption(zip::AesMode::Aes256, pw);
        }
        if item.is_dir {
            z.add_directory(format!("{}/", item.name), o)
                .map_err(|e| Error::Io(e.to_string()))?;
            continue;
        }
        let stored = s.store_compressed && already_compressed(&item.path);
        o = o
            .compression_method(if stored { M::Stored } else { method })
            .compression_level(if stored { None } else { level })
            .large_file(item.size >= 0xFFFF_FFFF);
        z.start_file(item.name.as_str(), o)
            .map_err(|e| Error::Io(e.to_string()))?;
        let mut r = reader(item, done, total, progress, cancel)?;
        io::copy(&mut r, &mut z).map_err(Error::from)?;
    }
    if let Some(c) = s.comment.as_deref().filter(|c| !c.is_empty()) {
        z.set_comment(c).map_err(|e| Error::Io(e.to_string()))?;
    }
    let mut out = z.finish().map_err(|e| Error::Io(e.to_string()))?;
    out.flush().map_err(io_err)?;
    Ok(())
}

#[allow(clippy::too_many_arguments, clippy::many_single_char_names)]
fn write_7z(
    file: File,
    items: &[Source],
    s: &Settings,
    done: &Cell<u64>,
    total: u64,
    progress: OnProgress<'_>,
    cancel: &Cancel,
) -> Result<()> {
    use sevenz_rust2::encoder_options::{
        AesEncoderOptions, Bzip2Options, Lzma2Options, PpmdOptions, ZstandardOptions,
    };
    use sevenz_rust2::{
        ArchiveEntry, ArchiveWriter, EncoderConfiguration, EncoderMethod, SourceReader,
    };
    let sz = |e: sevenz_rust2::Error| match e {
        sevenz_rust2::Error::Io(io, _) => Error::from(io),
        other => Error::Io(other.to_string()),
    };
    let mut w = ArchiveWriter::new(BufWriter::new(file)).map_err(sz)?;
    let n = threads(s);
    let main: EncoderConfiguration = match (s.level, s.method) {
        (Level::Store, _) => EncoderMethod::COPY.into(),
        (_, Some(Method::Ppmd)) => PpmdOptions::from_level(s.level.nine()).into(),
        (_, Some(Method::Bzip2)) => Bzip2Options::from_level(s.level.nine().max(1)).into(),
        (_, Some(Method::Zstd)) => {
            ZstandardOptions::from_level(u32::try_from(s.level.zstd()).unwrap_or(9)).into()
        }
        _ if n > 1 => Lzma2Options::from_level_mt(s.level.nine(), n, 0).into(),
        _ => Lzma2Options::from_level(s.level.nine()).into(),
    };
    let methods = |m: EncoderConfiguration| -> Vec<EncoderConfiguration> {
        match s.password.as_deref() {
            Some(pw) => vec![AesEncoderOptions::new(pw.into()).into(), m],
            None => vec![m],
        }
    };
    w.set_encrypt_header(s.password.is_some() && s.encrypt_names);
    let entry = |item: &Source| {
        if item.is_dir {
            ArchiveEntry::new_directory(&item.name)
        } else {
            ArchiveEntry::from_path(&item.path, item.name.clone())
        }
    };
    for item in items.iter().filter(|i| i.is_dir || i.size == 0) {
        w.push_archive_entry::<File>(entry(item), None)
            .map_err(sz)?;
    }
    let (plain, packed): (Vec<&Source>, Vec<&Source>) = items
        .iter()
        .filter(|i| !i.is_dir && i.size > 0)
        .partition(|i| !(s.store_compressed && already_compressed(&i.path)));
    for (group, how) in [(plain, main.clone()), (packed, EncoderMethod::COPY.into())] {
        if group.is_empty() {
            continue;
        }
        w.set_content_methods(methods(how));
        if s.solid {
            let entries: Vec<ArchiveEntry> = group.iter().map(|i| entry(i)).collect();
            let readers = group
                .iter()
                .map(|i| reader(i, done, total, progress, cancel).map(SourceReader::new))
                .collect::<Result<Vec<_>>>()?;
            w.push_archive_entries(entries, readers).map_err(sz)?;
        } else {
            for item in group {
                let r = reader(item, done, total, progress, cancel)?;
                w.push_archive_entry(entry(item), Some(r)).map_err(sz)?;
            }
        }
        cancel.check().map_err(Error::from)?;
    }
    let mut out = w.finish().map_err(Error::from)?;
    out.flush().map_err(io_err)?;
    Ok(())
}

/// The compressing writer for a tar family or single-file format.
fn compressor<'a>(
    format: Format,
    s: &Settings,
    out: BufWriter<File>,
) -> Result<Box<dyn FinishWrite + 'a>> {
    Ok(match format {
        Format::Tar => Box::new(out),
        Format::TarGz | Format::Gz => Box::new(flate2::write::GzEncoder::new(
            out,
            flate2::Compression::new(s.level.nine().max(1)),
        )),
        Format::TarBz2 | Format::Bz2 => Box::new(bzip2::write::BzEncoder::new(
            out,
            bzip2::Compression::new(s.level.nine().clamp(1, 9)),
        )),
        Format::TarXz | Format::Xz => Box::new(
            lzma_rust2::XzWriter::new(out, lzma_rust2::XzOptions::with_preset(s.level.nine()))
                .map_err(io_err)?,
        ),
        Format::TarZst | Format::Zst => {
            let mut e = zstd::stream::write::Encoder::new(out, s.level.zstd()).map_err(io_err)?;
            let _ = e.multithread(threads(s));
            e.include_checksum(true).map_err(io_err)?;
            Box::new(e)
        }
        other => return Err(Error::Unsupported(other.name().into())),
    })
}

/// A writer that has to be told it is done (a compressor writes its trailer).
trait FinishWrite: Write {
    fn finish_box(self: Box<Self>) -> io::Result<()>;
}

impl FinishWrite for BufWriter<File> {
    fn finish_box(mut self: Box<Self>) -> io::Result<()> {
        self.flush()
    }
}

impl FinishWrite for flate2::write::GzEncoder<BufWriter<File>> {
    fn finish_box(self: Box<Self>) -> io::Result<()> {
        self.finish()?.flush()
    }
}

impl FinishWrite for bzip2::write::BzEncoder<BufWriter<File>> {
    fn finish_box(self: Box<Self>) -> io::Result<()> {
        self.finish()?.flush()
    }
}

impl FinishWrite for lzma_rust2::XzWriter<BufWriter<File>> {
    fn finish_box(self: Box<Self>) -> io::Result<()> {
        self.finish()?.flush()
    }
}

impl FinishWrite for zstd::stream::write::Encoder<'_, BufWriter<File>> {
    fn finish_box(self: Box<Self>) -> io::Result<()> {
        self.finish()?.flush()
    }
}

#[allow(clippy::too_many_arguments, clippy::many_single_char_names)]
fn write_tar(
    file: File,
    items: &[Source],
    s: &Settings,
    done: &Cell<u64>,
    total: u64,
    progress: OnProgress<'_>,
    cancel: &Cancel,
) -> Result<()> {
    let w = compressor(s.format, s, BufWriter::new(file))?;
    let mut b = tar::Builder::new(w);
    b.mode(tar::HeaderMode::Complete);
    for item in items {
        let meta = std::fs::metadata(&item.path).map_err(io_err)?;
        let mut h = tar::Header::new_gnu();
        h.set_metadata(&meta);
        if item.is_dir {
            h.set_size(0);
            b.append_data(&mut h, format!("{}/", item.name), io::empty())
                .map_err(io_err)?;
        } else {
            let r = reader(item, done, total, progress, cancel)?;
            b.append_data(&mut h, &item.name, r).map_err(Error::from)?;
        }
    }
    let w = b.into_inner().map_err(io_err)?;
    w.finish_box().map_err(io_err)
}

#[allow(clippy::too_many_arguments, clippy::many_single_char_names)]
fn write_single(
    file: File,
    item: &Source,
    s: &Settings,
    done: &Cell<u64>,
    total: u64,
    progress: OnProgress<'_>,
    cancel: &Cancel,
) -> Result<()> {
    let mut w = compressor(s.format, s, BufWriter::new(file))?;
    let mut r = reader(item, done, total, progress, cancel)?;
    io::copy(&mut r, &mut w).map_err(Error::from)?;
    w.finish_box().map_err(io_err)
}

/// Turn `archive` into a new archive at `target` with `s` (RAR into 7z, ZIP into
/// TAR.XZ...). It goes through a folder beside the target, removed after.
pub fn convert(
    archive: &Archive,
    target: &Path,
    s: &Settings,
    progress: OnProgress<'_>,
    cancel: &Cancel,
) -> Result<Vec<PathBuf>> {
    let parent = target
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    let work = parent.join(format!(".eon-zip-convert-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);
    let outcome = (|| {
        let plan = archive.plan(
            &work,
            &Extract {
                smart: false,
                ..Extract::default()
            },
        );
        archive.extract(&plan, progress, cancel)?;
        let mut tops: Vec<PathBuf> = std::fs::read_dir(&work)
            .map_err(io_err)?
            .flatten()
            .map(|e| e.path())
            .collect();
        tops.sort();
        create(&tops, target, s, progress, cancel)
    })();
    let _ = std::fs::remove_dir_all(&work);
    outcome
}

/// A count of bytes read, for when only the size of compressed output matters.
pub fn read_len(r: &mut dyn Read) -> io::Result<u64> {
    io::copy(r, &mut io::sink())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_zip_password_with_turkish_letters_is_not_portable() {
        assert!(portable_zip_password("pw g 123"));
        assert!(!portable_zip_password("parolağ"));
        assert!(!portable_zip_password("café"));
    }
}
