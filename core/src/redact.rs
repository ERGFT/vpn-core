// SPDX-License-Identifier: GPL-3.0-or-later
//! Секреты в `Debug`-выводе: вместо значения — `***`.
//!
//! У структур с токенами, UUID, паролями и ссылками `Debug` написан вручную:
//! любой будущий `?cfg` или `.expect()` иначе вывел бы секрет в журнал.

use std::fmt;

/// Печатается как `***`.
pub struct Redacted;

impl fmt::Debug for Redacted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("***")
    }
}

/// `Some(***)` или `None`: видно, задан ли секрет, но не он сам.
pub fn opt<T>(v: &Option<T>) -> Option<Redacted> {
    v.as_ref().map(|_| Redacted)
}
