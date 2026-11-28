// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 EON contributors
//
// Additional permission under GNU GPL version 3 section 7:
// see LICENSE-EXCEPTION.md (EON Module ABI Exception 1.0).

//! Opening an archive, planning an extraction, extracting, testing, previewing.

use crate::codepage::{self, Decoder};
use crate::format::{self, Format};
use crate::safe::{self, Refusal, Warning};
use crate::volume::{self, MultiReader};
use crate::{motw, time, Cancel, Counting, Error, OnProgress, Progress, Result};
use serde::{Deserialize, Serialize};
use std::cell::Cell;
use std::collections::{BTreeMap, HashSet};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// One entry as the window shows it.
#[derive(Debug, Clone, Serialize)]
pub struct Entry {
    pub index: usize,
    /// The name inside the archive, folders separated by `/`.
    pub name: String,
    pub is_dir: bool,
    /// Uncompressed size; for a single compressed file whose size is not stored, 0.
    pub size: u64,
    /// Compressed size where the format keeps one per entry.
    pub packed: Option<u64>,
    #[serde(skip)]
    pub modified: Option<SystemTime>,
    /// Seconds since 1970, for the window.
    pub modified_secs: Option<u64>,
    pub encrypted: bool,
    pub link: bool,
    #[serde(skip)]
    pub mode: Option<u32>,
}

/// An opened archive. Nothing is decompressed until asked.
pub struct Archive {
    pub path: PathBuf,
    pub parts: Vec<PathBuf>,
    pub format: Format,
    pub entries: Vec<Entry>,
    /// The code page names were stored in, when it was not UTF-8.
    pub encoding: Option<String>,
    pub comment: Option<String>,
    pub solid: bool,
    password: Option<String>,
    /// The "from the internet" mark of the archive, copied to what it writes.
    mark: Option<Vec<u8>>,
}

/// What to do when a file of the same name is already there.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Conflict {
    /// Keep both: the new one gets " (1)".
    #[default]
    Rename,
    Overwrite,
    Skip,
}

/// How to extract.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Extract {
    /// One top folder is used as it is; loose files get a folder named after
    /// the archive. Never a folder inside a folder, never files sprayed.
    pub smart: bool,
    /// Only these entries (and, for folders, what is inside them).
    pub only: Option<Vec<usize>>,
    /// Names are taken relative to this folder inside the archive.
    pub base: Option<String>,
    /// Drop the folders inside the archive (7-Zip's `e`).
    pub flatten: bool,
    pub conflict: Conflict,
    /// The most an extraction may write before asking (bytes).
    pub limit: u64,
    /// The person agreed to go past `limit`.
    pub allow_large: bool,
}

impl Default for Extract {
    fn default() -> Self {
        Extract {
            smart: true,
            only: None,
            base: None,
            flatten: false,
            conflict: Conflict::Rename,
            limit: 32 << 30,
            allow_large: false,
        }
    }
}

/// One entry and where it goes.
#[derive(Debug, Clone, Serialize)]
pub struct Item {
    pub index: usize,
    pub name: String,
    pub target: PathBuf,
    pub is_dir: bool,
    pub size: u64,
}

/// Everything about an extraction, decided before anything is written.
#[derive(Debug, Clone, Serialize)]
pub struct Plan {
    /// The folder everything goes into.
    pub root: PathBuf,
    pub items: Vec<Item>,
    pub refused: Vec<(String, Refusal)>,
    pub warnings: Vec<(String, Warning)>,
    /// Bytes that will be written.
    pub total: u64,
    /// `total` is past the limit; extraction needs `allow_large`.
    pub over_limit: bool,
    #[serde(skip)]
    limit: u64,
    #[serde(skip)]
    allow_large: bool,
}

/// What an extraction or a test did.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Report {
    pub files: usize,
    pub folders: usize,
    pub bytes: u64,
    /// Entries that could not be read, with the reason (a test goes on past them).
    pub failed: Vec<(String, String)>,
    /// Where the files went.
    pub root: Option<PathBuf>,
}

const SEVEN_Z_AES: [u8; 4] = [0x06, 0xF1, 0x07, 0x01];

fn io_err(e: impl std::fmt::Display) -> Error {
    Error::Io(e.to_string())
}

fn zip_err(e: zip::result::ZipError) -> Error {
    use zip::result::ZipError;
    match e {
        ZipError::InvalidPassword => Error::WrongPassword,
        ZipError::Io(io) => Error::from(io),
        ZipError::UnsupportedArchive(m) if m.contains("assword") => Error::PasswordNeeded,
        other => {
            let text = other.to_string();
            if text.contains("checksum") || text.to_ascii_lowercase().contains("crc") {
                Error::Damaged(text)
            } else {
                Error::Format(text)
            }
        }
    }
}

fn sz_err(e: sevenz_rust2::Error) -> Error {
    use sevenz_rust2::Error as E;
    match e {
        E::PasswordRequired => Error::PasswordNeeded,
        E::MaybeBadPassword(_) => Error::WrongPassword,
        E::ChecksumVerificationFailed | E::NextHeaderCrcMismatch => Error::Damaged(e.to_string()),
        E::Io(io, _) | E::FileOpen(io, _) => Error::from(io),
        E::UnsupportedCompressionMethod(m) => Error::Unsupported(m),
        other => Error::Format(other.to_string()),
    }
}

fn secs(t: SystemTime) -> Option<u64> {
    t.duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

fn entry(index: usize, name: String, is_dir: bool, size: u64) -> Entry {
    Entry {
        index,
        name,
        is_dir,
        size,
        packed: None,
        modified: None,
        modified_secs: None,
        encrypted: false,
        link: false,
        mode: None,
    }
}

/// A ZIP entry's time: the UTC fields 7-Zip, Info-ZIP and EON Zip write
/// first, the DOS wall-clock fields otherwise.
fn zip_time<R: Read>(f: &zip::read::ZipFile<'_, R>) -> Option<SystemTime> {
    for extra in f.extra_data_fields() {
        match extra {
            zip::ExtraField::ExtendedTimestamp(t) => {
                if let Some(m) = t.mod_time() {
                    return Some(
                        std::time::UNIX_EPOCH + std::time::Duration::from_secs(u64::from(m)),
                    );
                }
            }
            zip::ExtraField::Ntfs(n) => {
                // 100 ns ticks since 1601.
                let unix = (n.mtime() / 10_000_000).checked_sub(11_644_473_600)?;
                return Some(std::time::UNIX_EPOCH + std::time::Duration::from_secs(unix));
            }
            _ => {}
        }
    }
    f.last_modified().and_then(|d| {
        time::from_fields(
            i64::from(d.year()),
            i64::from(d.month()),
            i64::from(d.day()),
            i64::from(d.hour()),
            i64::from(d.minute()),
            i64::from(d.second()),
        )
    })
}

fn open_reader(parts: &[PathBuf]) -> Result<MultiReader> {
    MultiReader::open(parts).map_err(io_err)
}

/// A decompressing reader over a single-file or tar stream.
fn stream(format: Format, r: MultiReader) -> Result<Box<dyn Read>> {
    Ok(match format {
        Format::Tar => Box::new(r),
        Format::TarGz | Format::Gz => Box::new(flate2::read::MultiGzDecoder::new(r)),
        Format::TarBz2 | Format::Bz2 => Box::new(bzip2::read::MultiBzDecoder::new(r)),
        Format::TarXz | Format::Xz => Box::new(lzma_rust2::XzReader::new(r, true)),
        Format::TarZst | Format::Zst => {
            Box::new(zstd::stream::read::Decoder::new(r).map_err(io_err)?)
        }
        other => {
            return Err(Error::Unsupported(format!(
                "{} is not a stream",
                other.name()
            )))
        }
    })
}

impl Archive {
    /// Open `path` (any part of a set of volumes). `language` breaks ties when
    /// guessing the code page of old names (`"tr"`).
    pub fn open(path: &Path, password: Option<&str>, language: Option<&str>) -> Result<Archive> {
        let parts = volume::parts_of(path);
        let first = parts.first().cloned().unwrap_or_else(|| path.to_path_buf());
        let head = format::head(&first).map_err(io_err)?;
        let joined = volume::joined_name(&first);
        let format = format::detect(&head, &joined)
            .ok_or_else(|| Error::Format(format!("{joined} is not an archive EON Zip knows")))?;
        let mut a = Archive {
            path: first.clone(),
            parts,
            format,
            entries: Vec::new(),
            encoding: None,
            comment: None,
            solid: false,
            password: password.filter(|p| !p.is_empty()).map(str::to_owned),
            mark: motw::read(&first),
        };
        match format {
            Format::Eonz => a.list_eonz()?,
            Format::Zip => a.list_zip(language)?,
            Format::SevenZ => a.list_7z()?,
            Format::Tar | Format::TarGz | Format::TarBz2 | Format::TarXz | Format::TarZst => {
                a.list_tar()?;
            }
            Format::Gz | Format::Bz2 | Format::Xz | Format::Zst => a.list_single()?,
            Format::Rar | Format::Iso | Format::Cab => {
                return Err(Error::Unsupported(format!(
                    "{} is opened through 7-Zip, which comes in a later version",
                    format.name()
                )))
            }
        }
        Ok(a)
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// Whether any entry needs a password.
    pub fn encrypted(&self) -> bool {
        self.entries.iter().any(|e| e.encrypted)
    }

    pub fn set_password(&mut self, password: Option<&str>) {
        self.password = password.filter(|p| !p.is_empty()).map(str::to_owned);
    }

    fn list_eonz(&mut self) -> Result<()> {
        let z = crate::eonz::Eonz::open(&self.path, self.password.as_deref())?;
        self.solid = true;
        self.comment = z.comment().map(str::to_owned);
        let encrypted = z.encrypted();
        for (i, e) in z.entries().into_iter().enumerate() {
            let mut x = entry(i, e.path, e.kind == crate::eonz::Kind::Dir, e.size);
            x.modified = e
                .mtime
                .map(|n| std::time::UNIX_EPOCH + std::time::Duration::from_nanos(n));
            x.modified_secs = x.modified.and_then(secs);
            x.encrypted = encrypted;
            x.link = e.kind == crate::eonz::Kind::Symlink;
            x.mode = e.mode;
            self.entries.push(x);
        }
        Ok(())
    }

    fn list_zip(&mut self, language: Option<&str>) -> Result<()> {
        let mut z = zip::ZipArchive::new(open_reader(&self.parts)?).map_err(zip_err)?;
        let comment = String::from_utf8_lossy(z.comment()).trim().to_owned();
        self.comment = (!comment.is_empty()).then_some(comment);
        let mut raw: Vec<(Vec<u8>, String)> = Vec::with_capacity(z.len());
        for i in 0..z.len() {
            let f = z.by_index_raw(i).map_err(zip_err)?;
            let mut e = entry(i, String::new(), f.is_dir(), f.size());
            e.packed = Some(f.compressed_size());
            e.modified = zip_time(&f);
            e.modified_secs = e.modified.and_then(secs);
            e.encrypted = f.encrypted();
            e.link = f.is_symlink();
            e.mode = f.unix_mode();
            let stored = f.name_raw().to_vec();
            let read_as = f.name().map_or_else(
                |_| String::from_utf8_lossy(&stored).into_owned(),
                std::borrow::Cow::into_owned,
            );
            raw.push((stored, read_as));
            self.entries.push(e);
        }
        // Names the library read as CP437 because the UTF-8 flag was not set.
        let guessed: Vec<&[u8]> = raw
            .iter()
            .filter(|(r, n)| std::str::from_utf8(r).ok() != Some(n.as_str()))
            .map(|(r, _)| r.as_slice())
            .collect();
        let decoder = if guessed.is_empty() {
            Decoder::Utf8
        } else {
            codepage::detect(&guessed, language)
        };
        if !guessed.is_empty() && decoder != Decoder::Utf8 {
            self.encoding = Some(decoder.label());
        }
        for (e, (stored, read_as)) in self.entries.iter_mut().zip(raw) {
            let text = if std::str::from_utf8(&stored).ok() == Some(read_as.as_str()) {
                read_as
            } else {
                decoder.decode(&stored).unwrap_or(read_as)
            };
            e.name = text.replace('\\', "/");
        }
        Ok(())
    }

    fn sz_password(&self) -> sevenz_rust2::Password {
        self.password
            .as_deref()
            .map_or_else(sevenz_rust2::Password::empty, sevenz_rust2::Password::from)
    }

    fn list_7z(&mut self) -> Result<()> {
        let mut r = open_reader(&self.parts)?;
        let a = sevenz_rust2::Archive::read(&mut r, &self.sz_password()).map_err(sz_err)?;
        self.solid = a.is_solid;
        let encrypted = a.blocks.iter().any(|b| {
            b.coders
                .iter()
                .any(|c| c.encoder_method_id() == SEVEN_Z_AES)
        });
        for (i, f) in a.files.iter().enumerate() {
            let mut e = entry(i, f.name().replace('\\', "/"), f.is_directory(), f.size());
            if f.has_last_modified_date {
                let t: SystemTime = f.last_modified_date().into();
                e.modified = Some(t);
                e.modified_secs = secs(t);
            }
            e.encrypted = encrypted && f.has_stream();
            let attrs = f.windows_attributes();
            // 7-Zip keeps Unix modes in the high half when bit 15 is set.
            if attrs & 0x8000 != 0 {
                let mode = attrs >> 16;
                e.mode = Some(mode);
                e.link = mode & 0o170_000 == 0o120_000;
            }
            e.link |= attrs & 0x400 != 0;
            self.entries.push(e);
        }
        Ok(())
    }

    fn list_tar(&mut self) -> Result<()> {
        let s = stream(self.format, open_reader(&self.parts)?)?;
        let mut t = tar::Archive::new(s);
        for (i, item) in t.entries().map_err(io_err)?.enumerate() {
            let item = item.map_err(|e| Error::Format(e.to_string()))?;
            let h = item.header();
            let kind = h.entry_type();
            let name = String::from_utf8_lossy(&item.path_bytes()).replace('\\', "/");
            let mut e = entry(i, name, kind.is_dir(), item.size());
            e.link = kind.is_symlink() || kind.is_hard_link();
            e.mode = h.mode().ok();
            if let Ok(m) = h.mtime() {
                e.modified = Some(std::time::UNIX_EPOCH + std::time::Duration::from_secs(m));
                e.modified_secs = Some(m);
            }
            if kind.is_file() || kind.is_dir() || e.link || kind == tar::EntryType::Continuous {
                self.entries.push(e);
            } else {
                // Devices, fifos and metadata headers: never written; keep the
                // index so extraction lines up.
                e.link = true;
                self.entries.push(e);
            }
        }
        Ok(())
    }

    fn list_single(&mut self) -> Result<()> {
        let joined = volume::joined_name(&self.path);
        let mut name = joined
            .rsplit_once('.')
            .map_or(joined.as_str(), |(s, _)| s)
            .to_owned();
        let mut size = 0;
        if self.format == Format::Gz {
            let mut r = open_reader(&self.parts)?;
            let g = flate2::read::GzDecoder::new(&mut r);
            if let Some(stored) = g.header().and_then(|h| h.filename()) {
                let stored = String::from_utf8_lossy(stored).into_owned();
                if !stored.is_empty() {
                    name = stored;
                }
            }
            // ISIZE: the size modulo 4 GiB, in the last four bytes.
            let len = r.len();
            if len >= 4 {
                use std::io::Seek;
                let mut tail = [0u8; 4];
                r.seek(io::SeekFrom::Start(len - 4)).map_err(io_err)?;
                r.read_exact(&mut tail).map_err(io_err)?;
                size = u64::from(u32::from_le_bytes(tail));
            }
        }
        self.entries.push(entry(0, name, false, size));
        Ok(())
    }

    /// Where every chosen entry goes, what is refused, what is worth a warning.
    // One decision in one place, read top to bottom: choose, refuse, place.
    #[allow(clippy::too_many_lines)]
    pub fn plan(&self, dest: &Path, how: &Extract) -> Plan {
        let base = how
            .base
            .as_deref()
            .map(|b| b.trim_matches('/').to_owned())
            .filter(|b| !b.is_empty());
        // The chosen entries: listed ones, and everything inside a listed folder.
        let chosen: Vec<&Entry> = match &how.only {
            None => self
                .entries
                .iter()
                .filter(|e| {
                    base.as_ref()
                        .is_none_or(|b| e.name.starts_with(&format!("{b}/")))
                })
                .collect(),
            Some(ids) => {
                let picked: Vec<&Entry> = self
                    .entries
                    .iter()
                    .filter(|e| ids.contains(&e.index))
                    .collect();
                let folders: Vec<String> = picked
                    .iter()
                    .filter(|e| e.is_dir)
                    .map(|e| format!("{}/", e.name.trim_end_matches('/')))
                    .collect();
                self.entries
                    .iter()
                    .filter(|e| {
                        ids.contains(&e.index)
                            || folders.iter().any(|f| e.name.starts_with(f.as_str()))
                    })
                    .collect()
            }
        };
        let mut refused = Vec::new();
        let mut warnings = Vec::new();
        let mut rel: Vec<(&Entry, PathBuf)> = Vec::new();
        for e in chosen {
            if e.link {
                refused.push((e.name.clone(), Refusal::Link));
                continue;
            }
            let name = match &base {
                Some(b) => e.name.strip_prefix(&format!("{b}/")).unwrap_or(&e.name),
                None => e.name.as_str(),
            };
            let name = if how.flatten && !e.is_dir {
                name.rsplit('/').next().unwrap_or(name)
            } else {
                name
            };
            if how.flatten && e.is_dir {
                continue;
            }
            match safe::entry_path(name) {
                Ok(p) => {
                    for w in safe::warnings(&e.name) {
                        warnings.push((e.name.clone(), w));
                    }
                    rel.push((e, p));
                }
                Err(Refusal::Empty) if e.is_dir => {}
                Err(r) => refused.push((e.name.clone(), r)),
            }
        }
        // Smart: one top folder stays; anything else gets the archive's own.
        let mut root = dest.to_path_buf();
        if how.smart {
            let tops: HashSet<&std::ffi::OsStr> = rel
                .iter()
                .filter_map(|(_, p)| p.components().next().map(std::path::Component::as_os_str))
                .collect();
            let single_folder = tops.len() == 1
                && rel
                    .iter()
                    .any(|(e, p)| e.is_dir || p.components().count() > 1);
            let single_file = rel.len() == 1 && !rel[0].0.is_dir;
            if single_folder {
                if let Some(top) = tops.into_iter().next() {
                    let wanted = dest.join(top);
                    let unique = unique_dir(&wanted);
                    if unique != wanted {
                        // The folder is taken: rename the top folder, not merge into it.
                        let new_top = unique
                            .file_name()
                            .map(std::ffi::OsStr::to_os_string)
                            .unwrap_or_default();
                        for (_, p) in &mut rel {
                            let rest: PathBuf = p.components().skip(1).collect();
                            *p = PathBuf::from(&new_top).join(rest);
                        }
                    }
                }
            } else if !single_file && !rel.is_empty() {
                let stem = archive_stem(&self.path);
                root = unique_dir(&dest.join(stem));
            }
        }
        let mut items = Vec::new();
        let mut taken: HashSet<PathBuf> = HashSet::new();
        let mut total = 0u64;
        for (e, p) in rel {
            let mut target = root.join(&p);
            if !e.is_dir {
                let exists = target.exists() || taken.contains(&target);
                if exists {
                    match how.conflict {
                        Conflict::Skip => continue,
                        Conflict::Overwrite => {}
                        Conflict::Rename => target = unique_file(&target, &taken),
                    }
                }
                taken.insert(target.clone());
                total += e.size;
            }
            items.push(Item {
                index: e.index,
                name: e.name.clone(),
                target,
                is_dir: e.is_dir,
                size: e.size,
            });
        }
        Plan {
            root,
            items,
            refused,
            warnings,
            total,
            over_limit: total > how.limit,
            limit: how.limit,
            allow_large: how.allow_large,
        }
    }

    /// Write what `plan` says. Partly written files are removed if it fails.
    pub fn extract(
        &self,
        plan: &Plan,
        progress: OnProgress<'_>,
        cancel: &Cancel,
    ) -> Result<Report> {
        if plan.over_limit && !plan.allow_large {
            return Err(Error::TooLarge {
                declared: plan.total,
                limit: plan.limit,
            });
        }
        std::fs::create_dir_all(&plan.root).map_err(io_err)?;
        let root = std::fs::canonicalize(&plan.root).map_err(io_err)?;
        let mut report = Report {
            root: Some(plan.root.clone()),
            ..Report::default()
        };
        for item in plan.items.iter().filter(|i| i.is_dir) {
            std::fs::create_dir_all(&item.target).map_err(io_err)?;
            report.folders += 1;
        }
        let wanted: BTreeMap<usize, &Item> = plan
            .items
            .iter()
            .filter(|i| !i.is_dir)
            .map(|i| (i.index, i))
            .collect();
        let done = Cell::new(0u64);
        let cap = if plan.allow_large {
            u64::MAX
        } else {
            plan.limit
        };
        let mut write = |item: &Item, data: &mut dyn Read| -> Result<()> {
            let target = &item.target;
            let parent = target.parent().unwrap_or(&plan.root);
            std::fs::create_dir_all(parent).map_err(io_err)?;
            // A link already on disk must not lead outside the root.
            let real = std::fs::canonicalize(parent).map_err(io_err)?;
            if !real.starts_with(&root) {
                return Err(Error::Io(format!(
                    "{} leads outside the folder",
                    parent.display()
                )));
            }
            let mut file = std::fs::File::create(target).map_err(io_err)?;
            let mut r = Counting {
                inner: data,
                done: &done,
                total: plan.total,
                name: &item.name,
                progress,
                cancel,
                last: Cell::new(done.get()),
            };
            // An entry may not write more than it declared (sizes can lie),
            // and nothing past the limit.
            let allowed = if item.size > 0 { item.size } else { cap };
            let written = io::copy(&mut (&mut r).take(allowed.saturating_add(1)), &mut file);
            let outcome = match written {
                Ok(n) if n > allowed => Err(Error::Damaged(format!(
                    "{} holds more than it declares",
                    item.name
                ))),
                Ok(n) if done.get() > cap => Err(Error::TooLarge {
                    declared: n,
                    limit: cap,
                }),
                Ok(_) => Ok(()),
                Err(e) => Err(Error::from(e)),
            };
            drop(file);
            if let Err(e) = outcome {
                let _ = std::fs::remove_file(target);
                return Err(e);
            }
            if let Some(mark) = &self.mark {
                motw::write(target, mark);
            }
            report.files += 1;
            report.bytes += std::fs::metadata(target).map_or(0, |m| m.len());
            Ok(())
        };
        self.each(
            &wanted.keys().copied().collect(),
            cancel,
            &mut |index, data| {
                if let Some(item) = wanted.get(&index) {
                    write(item, data)
                } else {
                    Ok(())
                }
            },
        )?;
        // Times and permissions last, so writing into a folder does not touch its time.
        for item in &plan.items {
            if let Some(e) = self.entries.get(item.index) {
                restore(&item.target, e);
            }
        }
        (progress)(&Progress {
            done: done.get(),
            total: plan.total,
            name: String::new(),
        });
        Ok(report)
    }

    /// Read every byte of every entry and check it. Goes on past a damaged
    /// entry so the report names all of them.
    pub fn test(&self, progress: OnProgress<'_>, cancel: &Cancel) -> Result<Report> {
        let total: u64 = self.entries.iter().map(|e| e.size).sum();
        let done = Cell::new(0u64);
        let mut report = Report::default();
        let all: HashSet<usize> = self
            .entries
            .iter()
            .filter(|e| !e.is_dir)
            .map(|e| e.index)
            .collect();
        let result = self.each(
            &all.iter().copied().collect(),
            cancel,
            &mut |index, data| {
                let name = self
                    .entries
                    .get(index)
                    .map(|e| e.name.as_str())
                    .unwrap_or_default();
                let mut r = Counting {
                    inner: data,
                    done: &done,
                    total,
                    name,
                    progress,
                    cancel,
                    last: Cell::new(done.get()),
                };
                match io::copy(&mut r, &mut io::sink()) {
                    Ok(n) => {
                        report.files += 1;
                        report.bytes += n;
                        Ok(())
                    }
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => Err(Error::Cancelled),
                    Err(e) => {
                        report.failed.push((name.to_owned(), e.to_string()));
                        // 7z's solid stream cannot go on past broken data.
                        if self.format == Format::SevenZ && self.solid {
                            Err(Error::Damaged(e.to_string()))
                        } else {
                            Ok(())
                        }
                    }
                }
            },
        );
        match result {
            Ok(()) => Ok(report),
            Err(Error::Damaged(m)) => {
                if report.failed.is_empty() {
                    report.failed.push((String::new(), m));
                }
                Ok(report)
            }
            Err(e) => Err(e),
        }
    }

    /// The first `max` bytes of one entry, for a preview.
    pub fn peek(&self, index: usize, max: usize) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        self.each(
            &std::iter::once(index).collect(),
            &Cancel::default(),
            &mut |i, data| {
                if i == index {
                    data.take(max as u64)
                        .read_to_end(&mut out)
                        .map_err(Error::from)?;
                }
                Ok(())
            },
        )?;
        Ok(out)
    }

    /// Call `f` with the data of each wanted entry, in the archive's own order.
    /// Entries not wanted are skipped where the format allows it and read
    /// through where it does not (a 7z solid stream, a tar).
    fn each(
        &self,
        wanted: &HashSet<usize>,
        cancel: &Cancel,
        f: &mut dyn FnMut(usize, &mut dyn Read) -> Result<()>,
    ) -> Result<()> {
        match self.format {
            Format::Eonz => {
                let z = crate::eonz::Eonz::open(&self.path, self.password.as_deref())?;
                let mut order: Vec<usize> = wanted.iter().copied().collect();
                order.sort_unstable();
                for i in order {
                    cancel.check().map_err(Error::from)?;
                    let Some(e) = self.entries.get(i) else {
                        continue;
                    };
                    if e.is_dir {
                        continue;
                    }
                    let mut r = z.reader(i)?;
                    f(i, &mut r)?;
                    // Read to the end so the whole file's checksum is checked.
                    io::copy(&mut r, &mut io::sink()).map_err(|e| Error::Damaged(e.to_string()))?;
                }
                Ok(())
            }
            Format::Zip => {
                let mut z = zip::ZipArchive::new(open_reader(&self.parts)?).map_err(zip_err)?;
                let mut order: Vec<usize> = wanted.iter().copied().collect();
                order.sort_unstable();
                for i in order {
                    cancel.check().map_err(Error::from)?;
                    let encrypted = self.entries.get(i).is_some_and(|e| e.encrypted);
                    let file = if encrypted {
                        let pw = self.password.as_deref().ok_or(Error::PasswordNeeded)?;
                        z.by_index_decrypt(i, pw.as_bytes())
                    } else {
                        z.by_index(i)
                    };
                    let mut file = file.map_err(zip_err)?;
                    f(i, &mut file)?;
                    // Read to the end so the CRC is checked even if `f` stopped early.
                    io::copy(&mut file, &mut io::sink())
                        .map_err(|e| Error::Damaged(e.to_string()))?;
                }
                Ok(())
            }
            Format::SevenZ => {
                let mut r =
                    sevenz_rust2::ArchiveReader::new(open_reader(&self.parts)?, self.sz_password())
                        .map_err(sz_err)?;
                let base = r.archive().files.as_ptr() as usize;
                let size = std::mem::size_of::<sevenz_rust2::ArchiveEntry>().max(1);
                let mut failure: Option<Error> = None;
                let outcome = r.for_each_entries(|entry, data| {
                    if cancel.stopped() {
                        failure = Some(Error::Cancelled);
                        return Ok(false);
                    }
                    let index = (std::ptr::from_ref(entry) as usize).wrapping_sub(base) / size;
                    if wanted.contains(&index) {
                        if let Err(e) = f(index, data) {
                            failure = Some(e);
                            return Ok(false);
                        }
                    }
                    // A solid stream has to be read through in order.
                    io::copy(data, &mut io::sink())?;
                    Ok(true)
                });
                if let Some(e) = failure {
                    return Err(e);
                }
                outcome.map_err(sz_err)
            }
            Format::Tar | Format::TarGz | Format::TarBz2 | Format::TarXz | Format::TarZst => {
                let s = stream(self.format, open_reader(&self.parts)?)?;
                let mut t = tar::Archive::new(s);
                for (i, item) in t.entries().map_err(io_err)?.enumerate() {
                    cancel.check().map_err(Error::from)?;
                    let mut item = item.map_err(|e| Error::Damaged(e.to_string()))?;
                    if wanted.contains(&i) {
                        f(i, &mut item)?;
                    }
                }
                Ok(())
            }
            Format::Gz | Format::Bz2 | Format::Xz | Format::Zst => {
                let mut s = stream(self.format, open_reader(&self.parts)?)?;
                if wanted.contains(&0) {
                    f(0, &mut s)?;
                }
                Ok(())
            }
            Format::Rar | Format::Iso | Format::Cab => {
                Err(Error::Unsupported(self.format.name().into()))
            }
        }
    }
}

/// Times and, on Unix, permissions (never set-user-id or set-group-id).
fn restore(path: &Path, e: &Entry) {
    if let Some(t) = e.modified {
        if let Ok(f) = std::fs::File::options().write(true).open(path) {
            let _ = f.set_modified(t);
        }
    }
    #[cfg(unix)]
    if let Some(mode) = e.mode {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode & 0o777));
    }
}

/// The archive's name without its archive extensions.
pub fn archive_stem(path: &Path) -> String {
    let name = volume::joined_name(path);
    let lower = name.to_ascii_lowercase();
    for ext in [".tar.gz", ".tar.bz2", ".tar.xz", ".tar.zst"] {
        if lower.ends_with(ext) {
            return name[..name.len() - ext.len()].to_owned();
        }
    }
    name.rsplit_once('.')
        .map_or(name.as_str(), |(s, _)| s)
        .to_owned()
}

fn unique_dir(p: &Path) -> PathBuf {
    if !p.exists() {
        return p.to_path_buf();
    }
    let name = p
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    (1..u32::MAX)
        .map(|n| p.with_file_name(format!("{name} ({n})")))
        .find(|c| !c.exists())
        .unwrap_or_else(|| p.to_path_buf())
}

fn unique_file(p: &Path, taken: &HashSet<PathBuf>) -> PathBuf {
    let stem = p
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let ext = p
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy()))
        .unwrap_or_default();
    (1..u32::MAX)
        .map(|n| p.with_file_name(format!("{stem} ({n}){ext}")))
        .find(|c| !c.exists() && !taken.contains(c))
        .unwrap_or_else(|| p.to_path_buf())
}

/// Write `data` to `w` and flush — used by tests and the window's previews.
pub fn copy_all(data: &mut dyn Read, w: &mut dyn Write) -> io::Result<u64> {
    io::copy(data, w)
}
