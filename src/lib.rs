// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 EON contributors
//
// Additional permission under GNU GPL version 3 section 7:
// see LICENSE-EXCEPTION.md (EON Module ABI Exception 1.0).

//! The core of EON Zip (plan madde 49): open, list, extract, test and create
//! archives, split and join volumes, hash files, convert between formats.
//!
//! It is a library with no window. Every extraction is planned first
//! ([`Archive::plan`]): where each entry goes, what is refused and why, what is
//! worth a warning. Nothing is written outside the folder a person chose, and
//! there is no option that allows it ([`safe`]).
//!
//! ```no_run
//! # use eon_zip_core::*;
//! # use std::path::Path;
//! let archive = Archive::open(Path::new("photos.zip"), None, None)?;
//! let plan = archive.plan(Path::new("Downloads"), &Extract::default());
//! archive.extract(&plan, &|_| {}, &Cancel::default())?;
//! # Ok::<(), Error>(())
//! ```

pub mod codepage;
pub mod create;
pub mod eonz;
pub mod format;
pub mod hash;
pub mod motw;
pub mod read;
pub mod safe;
pub mod time;
pub mod volume;

pub use create::{convert, create, portable_zip_password, Level, Method, Settings};
pub use format::Format;
pub use read::{Archive, Conflict, Entry, Extract, Item, Plan, Report};

use serde::Serialize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// What went wrong, in a form the window chooses its words by ([`Error::code`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Reading or writing a file failed.
    Io(String),
    /// Not an archive EON Zip reads, or damaged beyond reading.
    Format(String),
    /// The archive is encrypted and no password was given.
    PasswordNeeded,
    /// The password does not open it.
    WrongPassword,
    /// Data does not match its checksum.
    Damaged(String),
    /// A format EON Zip recognises but does not read yet (parity.md).
    Unsupported(String),
    /// Bigger than the limit a person agreed to (an archive bomb, or a lie in
    /// the headers).
    TooLarge { declared: u64, limit: u64 },
    /// The person stopped it.
    Cancelled,
}

impl Error {
    pub fn code(&self) -> &'static str {
        match self {
            Error::Io(_) => "disk",
            Error::Format(_) => "format",
            Error::PasswordNeeded => "password_needed",
            Error::WrongPassword => "wrong_password",
            Error::Damaged(_) => "damaged",
            Error::Unsupported(_) => "unsupported",
            Error::TooLarge { .. } => "too_large",
            Error::Cancelled => "cancelled",
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(m) | Error::Format(m) | Error::Damaged(m) | Error::Unsupported(m) => {
                f.write_str(m)
            }
            Error::PasswordNeeded => f.write_str("a password is needed"),
            Error::WrongPassword => f.write_str("the password does not open it"),
            Error::TooLarge { declared, limit } => {
                write!(f, "{declared} bytes would be written; the limit is {limit}")
            }
            Error::Cancelled => f.write_str("stopped"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        if e.kind() == std::io::ErrorKind::Interrupted && e.to_string() == "cancelled" {
            Error::Cancelled
        } else {
            Error::Io(e.to_string())
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// How far an operation is.
#[derive(Debug, Clone, Serialize)]
pub struct Progress {
    /// Bytes done and the whole, uncompressed.
    pub done: u64,
    pub total: u64,
    /// The entry or file being worked on.
    pub name: String,
}

/// Called often; a window throttles it.
pub type OnProgress<'a> = &'a (dyn Fn(&Progress) + Send + Sync);

/// A stop switch shared with the operation.
#[derive(Debug, Clone, Default)]
pub struct Cancel(Arc<AtomicBool>);

impl Cancel {
    pub fn stop(&self) {
        self.0.store(true, Ordering::Relaxed);
    }

    pub fn stopped(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }

    pub(crate) fn check(&self) -> std::io::Result<()> {
        if self.stopped() {
            Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "cancelled",
            ))
        } else {
            Ok(())
        }
    }
}

/// A reader that counts what passes, reports it, and stops when told to.
pub(crate) struct Counting<'a, R> {
    pub inner: R,
    pub done: &'a std::cell::Cell<u64>,
    pub total: u64,
    pub name: &'a str,
    pub progress: OnProgress<'a>,
    pub cancel: &'a Cancel,
    pub last: std::cell::Cell<u64>,
}

impl<R: std::io::Read> std::io::Read for Counting<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.cancel.check()?;
        let n = self.inner.read(buf)?;
        let done = self.done.get() + n as u64;
        self.done.set(done);
        // Report every 256 KiB, and at the end.
        if done - self.last.get() >= 256 * 1024 || n == 0 {
            self.last.set(done);
            (self.progress)(&Progress {
                done,
                total: self.total,
                name: self.name.to_owned(),
            });
        }
        Ok(n)
    }
}
