// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 EON contributors
//
// Additional permission under GNU GPL version 3 section 7:
// see LICENSE-EXCEPTION.md (EON Module ABI Exception 1.0).

//! Calendar dates without a date library: ZIP stores wall-clock fields,
//! everything else a count of seconds.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's
/// algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Year, month, day, hour, minute, second (UTC) to a time.
pub fn from_fields(y: i64, mo: i64, d: i64, h: i64, mi: i64, s: i64) -> Option<SystemTime> {
    let secs = days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + s;
    u64::try_from(secs)
        .ok()
        .map(|s| UNIX_EPOCH + Duration::from_secs(s))
}

/// A time to its UTC fields.
pub fn to_fields(t: SystemTime) -> (i64, i64, i64, i64, i64, i64) {
    let secs = t
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(0));
    let (y, m, d) = civil_from_days(secs.div_euclid(86_400));
    let rem = secs.rem_euclid(86_400);
    (y, m, d, rem / 3600, rem % 3600 / 60, rem % 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        for (y, mo, d, h, mi, s) in [
            (1980, 1, 1, 0, 0, 0),
            (2026, 11, 22, 13, 45, 7),
            (2000, 2, 29, 23, 59, 58),
        ] {
            let t = from_fields(y, mo, d, h, mi, s).unwrap_or(UNIX_EPOCH);
            assert_eq!(to_fields(t), (y, mo, d, h, mi, s));
        }
    }
}
