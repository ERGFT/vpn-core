// SPDX-License-Identifier: GPL-3.0-or-later
//! Запись файлов: атомарно и без окна с чужими правами.

use std::io::Write;
use std::path::{Path, PathBuf};

/// Записать `data` в `path` через временный файл рядом.
///
/// * временный файл создаётся флагом `create_new` (`O_EXCL`): подложенный
///   симлинк с тем же именем не открывается, а удаляется;
/// * права (`mode`, только Unix) задаются при создании, а не после, —
///   нет окна, когда файл читаем всем;
/// * на Windows права наследуются от каталога (у службы это каталог с
///   SDDL только для SYSTEM/Администраторов).
pub fn write_atomic(path: &Path, data: &[u8], mode: u32) -> std::io::Result<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    // remove_file удаляет сам симлинк, а не его цель.
    let _ = std::fs::remove_file(&tmp);

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;

    let written = (|| -> std::io::Result<()> {
        let mut f = opts.open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()
    })();
    if let Err(e) = written {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    std::fs::rename(&tmp, path).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })
}

/// Права существующего файла (Unix) или `0o600`, если файла нет.
pub fn existing_mode_or_private(path: &Path) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(m) = std::fs::metadata(path) {
            return m.permissions().mode() & 0o777;
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    0o600
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn dir() -> PathBuf {
        let d = std::env::temp_dir().join(format!("vpn-core-fsutil-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn created_private_and_replaces_symlink() {
        let d = dir();
        let target = d.join("victim");
        std::fs::write(&target, "do not touch").unwrap();
        let f = d.join("cfg.json");
        std::os::unix::fs::symlink(&target, d.join("cfg.json.tmp")).unwrap();

        write_atomic(&f, b"secret", 0o600).unwrap();

        assert_eq!(std::fs::read(&f).unwrap(), b"secret");
        assert_eq!(
            std::fs::metadata(&f).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(std::fs::read(&target).unwrap(), b"do not touch"); // цель не тронута
        let _ = std::fs::remove_dir_all(&d);
    }
}
