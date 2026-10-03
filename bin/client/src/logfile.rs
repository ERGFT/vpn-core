// SPDX-License-Identifier: GPL-3.0-or-later
//! Файл журнала (`--log-file`): только для владельца, с ротацией по размеру
//! во время работы.
//!
//! В журнале — имена и SNI серверов, адреса клиентов прокси: файл создаётся
//! с правами 0600 (Unix), а у уже существующего права сужаются. Больше
//! [`LIMIT`] — текущий уходит в `<файл>.old` (прежний `.old` заменяется),
//! пишется новый. Раньше это проверялось только при запуске, и журнал
//! долго работающей службы рос без предела.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// Предел размера файла журнала.
pub const LIMIT: u64 = 10 << 20;

fn open_private(path: &Path) -> io::Result<File> {
    let mut o = OpenOptions::new();
    o.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Права — при создании, а не после: иначе файл успел бы побыть
        // доступным всем.
        o.mode(0o600);
    }
    let f = o.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Файл мог остаться от прежней версии с правами по umask (0644).
        if f.metadata()?.permissions().mode() & 0o077 != 0 {
            f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
    }
    Ok(f)
}

/// Файл журнала с ротацией по размеру.
pub struct RotatingFile {
    path: PathBuf,
    file: File,
    written: u64,
    limit: u64,
}

impl RotatingFile {
    pub fn open(path: &Path, limit: u64) -> io::Result<Self> {
        let file = open_private(path)?;
        let written = file.metadata()?.len();
        let mut f = Self {
            path: path.to_path_buf(),
            file,
            written,
            limit,
        };
        if f.written >= f.limit {
            f.rotate()?;
        }
        Ok(f)
    }

    fn rotate(&mut self) -> io::Result<()> {
        let mut old = self.path.as_os_str().to_owned();
        old.push(".old");
        // Не вышло (нет прав на каталог) — пишем дальше в тот же файл, а не
        // теряем журнал.
        if std::fs::rename(&self.path, &old).is_ok() {
            self.file = open_private(&self.path)?;
            self.written = 0;
        }
        Ok(())
    }
}

impl Write for RotatingFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.written >= self.limit {
            self.rotate()?;
        }
        let n = self.file.write(buf)?;
        self.written += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::RotatingFile;
    use std::io::Write;

    #[test]
    fn rotates_at_limit_and_keeps_one_old_file() {
        let dir = std::env::temp_dir().join(format!("rc-logfile-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("client.log");
        let mut f = RotatingFile::open(&path, 100).unwrap();
        for _ in 0..3 {
            f.write_all(&[b'a'; 60]).unwrap();
            f.write_all(&[b'b'; 60]).unwrap();
        }
        let old = dir.join("client.log.old");
        assert!(old.exists(), "текущий ушёл в .old");
        assert!(std::fs::metadata(&path).unwrap().len() <= 120);
        assert!(std::fs::metadata(&old).unwrap().len() <= 120);
        // Файл больше предела при запуске — сразу в .old.
        std::fs::write(&path, [b'c'; 200]).unwrap();
        drop(RotatingFile::open(&path, 100).unwrap());
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
        assert_eq!(std::fs::metadata(&old).unwrap().len(), 200);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn only_owner_can_read() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("rc-logperm-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("client.log");
        drop(RotatingFile::open(&path, 100).unwrap());
        let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600);
        // Старый файл с правами 0644 — права сужаются.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        drop(RotatingFile::open(&path, 100).unwrap());
        assert_eq!(mode(&path), 0o600);
        std::fs::remove_dir_all(&dir).ok();
    }
}
