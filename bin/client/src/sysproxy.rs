// SPDX-License-Identifier: GPL-3.0-or-later
//! Системный прокси Windows (`--system-proxy`): браузеры и большинство
//! программ сами начинают ходить через HTTP-вход клиента.
//!
//! Настройки — в реестре текущего пользователя
//! (`HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`:
//! `ProxyEnable`, `ProxyServer`, `ProxyOverride`), после записи программам
//! сообщается об изменении (`InternetSetOption`). При выходе (Ctrl+C,
//! закрытие окна) прежние значения возвращаются. Если процесс убит
//! жёстко, выключить прокси — `reality-client --system-proxy-off`.

// Вне Windows часть кода нужна только тестам.
#![cfg_attr(not(windows), allow(dead_code))]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use anyhow::Result;

/// Адреса, которые идут мимо прокси: локальная сеть и этот компьютер.
pub const BYPASS: &str = "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;\
172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;\
172.29.*;172.30.*;172.31.*;192.168.*;<local>";

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Settings {
    pub enable: Option<u32>,
    pub server: Option<String>,
    pub bypass: Option<String>,
}

/// Адрес для системного прокси: «слушать везде» → 127.0.0.1.
pub fn proxy_server(addr: SocketAddr) -> String {
    let ip = match addr.ip() {
        ip if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        ip => ip,
    };
    SocketAddr::new(ip, addr.port()).to_string()
}

#[cfg(windows)]
mod win {
    use super::Settings;
    use std::io;
    use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
    use windows_sys::Win32::Networking::WinInet::{
        InternetSetOptionW, INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED,
    };
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegCreateKeyExW, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW,
        RegSetValueExW, HKEY, HKEY_CURRENT_USER, KEY_READ, KEY_WRITE, REG_DWORD, REG_SZ,
    };

    const KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }

    fn check(code: u32) -> io::Result<()> {
        if code == ERROR_SUCCESS {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(code as i32))
        }
    }

    struct Key(HKEY);
    impl Drop for Key {
        fn drop(&mut self) {
            unsafe { RegCloseKey(self.0) };
        }
    }

    fn open(write: bool) -> io::Result<Key> {
        open_key(KEY, write)
    }

    fn open_key(path: &str, write: bool) -> io::Result<Key> {
        let mut h: HKEY = std::ptr::null_mut();
        let access = if write {
            KEY_READ | KEY_WRITE
        } else {
            KEY_READ
        };
        // SAFETY: имя — строка с нулём в конце, h — место для результата.
        check(unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, wide(path).as_ptr(), 0, access, &mut h) })?;
        Ok(Key(h))
    }

    /// Строковое значение в разделе HKCU (`None` — удалить); раздела нет
    /// — создаётся.
    pub fn set_user_string(path: &str, name: &str, v: Option<&str>) -> io::Result<()> {
        let mut h: HKEY = std::ptr::null_mut();
        // SAFETY: имя — строка с нулём в конце, h — место для результата.
        check(unsafe {
            RegCreateKeyExW(
                HKEY_CURRENT_USER,
                wide(path).as_ptr(),
                0,
                std::ptr::null(),
                0,
                KEY_READ | KEY_WRITE,
                std::ptr::null(),
                &mut h,
                std::ptr::null_mut(),
            )
        })?;
        set_string(&Key(h), name, v)
    }

    /// Значение как байты и его тип; `None` — значения нет.
    fn query(k: &Key, name: &str) -> io::Result<Option<(u32, Vec<u8>)>> {
        let name = wide(name);
        let mut ty = 0u32;
        let mut len = 0u32;
        // SAFETY: сначала узнаём размер (буфер не передаём).
        let r = unsafe {
            RegQueryValueExW(
                k.0,
                name.as_ptr(),
                std::ptr::null(),
                &mut ty,
                std::ptr::null_mut(),
                &mut len,
            )
        };
        if r == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        check(r)?;
        let mut buf = vec![0u8; len as usize];
        // SAFETY: буфер длиной len, как сообщил реестр.
        check(unsafe {
            RegQueryValueExW(
                k.0,
                name.as_ptr(),
                std::ptr::null(),
                &mut ty,
                buf.as_mut_ptr(),
                &mut len,
            )
        })?;
        buf.truncate(len as usize);
        Ok(Some((ty, buf)))
    }

    fn query_dword(k: &Key, name: &str) -> io::Result<Option<u32>> {
        Ok(match query(k, name)? {
            Some((t, b)) if t == REG_DWORD && b.len() >= 4 => {
                Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
            }
            _ => None,
        })
    }

    fn query_string(k: &Key, name: &str) -> io::Result<Option<String>> {
        Ok(match query(k, name)? {
            Some((_, b)) => {
                let w: Vec<u16> = b
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|&c| u16::from_le_bytes(c))
                    .take_while(|&c| c != 0)
                    .collect();
                Some(String::from_utf16_lossy(&w))
            }
            None => None,
        })
    }

    fn delete(k: &Key, name: &str) -> io::Result<()> {
        // SAFETY: имя — строка с нулём в конце.
        let r = unsafe { RegDeleteValueW(k.0, wide(name).as_ptr()) };
        if r == ERROR_FILE_NOT_FOUND {
            return Ok(());
        }
        check(r)
    }

    fn set_dword(k: &Key, name: &str, v: Option<u32>) -> io::Result<()> {
        let Some(v) = v else { return delete(k, name) };
        let b = v.to_le_bytes();
        // SAFETY: 4 байта данных DWORD.
        check(unsafe { RegSetValueExW(k.0, wide(name).as_ptr(), 0, REG_DWORD, b.as_ptr(), 4) })
    }

    fn set_string(k: &Key, name: &str, v: Option<&str>) -> io::Result<()> {
        let Some(v) = v else { return delete(k, name) };
        let w = wide(v);
        // SAFETY: строка UTF-16 с нулём в конце, длина в байтах.
        check(unsafe {
            RegSetValueExW(
                k.0,
                wide(name).as_ptr(),
                0,
                REG_SZ,
                w.as_ptr().cast(),
                (w.len() * 2) as u32,
            )
        })
    }

    pub fn read() -> io::Result<Settings> {
        let k = open(false)?;
        Ok(Settings {
            enable: query_dword(&k, "ProxyEnable")?,
            server: query_string(&k, "ProxyServer")?,
            bypass: query_string(&k, "ProxyOverride")?,
        })
    }

    pub fn write(s: &Settings) -> io::Result<()> {
        let k = open(true)?;
        set_string(&k, "ProxyServer", s.server.as_deref())?;
        set_string(&k, "ProxyOverride", s.bypass.as_deref())?;
        set_dword(&k, "ProxyEnable", s.enable)?;
        // Сообщить программам, что настройки изменились.
        // SAFETY: параметры без буфера — так эти опции и вызываются.
        unsafe {
            InternetSetOptionW(
                std::ptr::null(),
                INTERNET_OPTION_SETTINGS_CHANGED,
                std::ptr::null(),
                0,
            );
            InternetSetOptionW(
                std::ptr::null(),
                INTERNET_OPTION_REFRESH,
                std::ptr::null(),
                0,
            );
        }
        Ok(())
    }
}

/// Строковое значение в HKCU (для автозапуска); `None` — удалить.
#[cfg(windows)]
pub fn set_user_string(path: &str, name: &str, v: Option<&str>) -> Result<()> {
    win::set_user_string(path, name, v).map_err(|e| anyhow::anyhow!("реестр HKCU\\{path}: {e}"))
}

/// Включённый системный прокси; при уничтожении возвращает прежние
/// настройки.
pub struct Guard {
    previous: Settings,
}

#[cfg(windows)]
pub fn enable(addr: SocketAddr) -> Result<Guard> {
    use anyhow::Context;
    let server = proxy_server(addr);
    let mut previous = win::read().context("чтение настроек прокси Windows")?;
    if previous.enable == Some(1) && previous.server.as_deref() == Some(server.as_str()) {
        // Прошлый запуск не успел вернуть настройки (процесс убит).
        tracing::warn!(
            "системный прокси уже указывал на этот клиент; при выходе он будет выключен"
        );
        previous.enable = Some(0);
    }
    win::write(&Settings {
        enable: Some(1),
        server: Some(server.clone()),
        bypass: Some(BYPASS.into()),
    })
    .context("запись настроек прокси Windows")?;
    tracing::info!(%server, "системный прокси Windows включён");
    Ok(Guard { previous })
}

#[cfg(not(windows))]
pub fn enable(_addr: SocketAddr) -> Result<Guard> {
    anyhow::bail!("--system-proxy пока есть только для Windows")
}

/// Выключить системный прокси (после жёсткого завершения клиента).
#[cfg(windows)]
pub fn disable() -> Result<()> {
    let mut s = win::read()?;
    s.enable = Some(0);
    win::write(&s)?;
    Ok(())
}

#[cfg(not(windows))]
pub fn disable() -> Result<()> {
    anyhow::bail!("--system-proxy-off есть только для Windows")
}

impl Drop for Guard {
    fn drop(&mut self) {
        #[cfg(windows)]
        match win::write(&self.previous) {
            Ok(()) => tracing::info!("системный прокси Windows: прежние настройки возвращены"),
            Err(e) => tracing::error!(
                error = %e,
                "не удалось вернуть настройки прокси Windows; выполните reality-client --system-proxy-off"
            ),
        }
        #[cfg(not(windows))]
        let _ = &self.previous;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_address() {
        assert_eq!(
            proxy_server("0.0.0.0:1080".parse().unwrap()),
            "127.0.0.1:1080"
        );
        assert_eq!(
            proxy_server("127.0.0.1:8080".parse().unwrap()),
            "127.0.0.1:8080"
        );
        assert_eq!(proxy_server("[::]:1080".parse().unwrap()), "127.0.0.1:1080");
    }

    /// Под Windows (в CI — под Wine): включить, проверить реестр,
    /// вернуть как было.
    #[cfg(windows)]
    #[test]
    fn enable_and_restore_roundtrip() {
        let before = win::read().unwrap();
        {
            let _g = enable("0.0.0.0:18080".parse().unwrap()).unwrap();
            let now = win::read().unwrap();
            assert_eq!(now.enable, Some(1));
            assert_eq!(now.server.as_deref(), Some("127.0.0.1:18080"));
            assert_eq!(now.bypass.as_deref(), Some(BYPASS));
        }
        assert_eq!(
            win::read().unwrap(),
            before,
            "настройки возвращены в точности"
        );
        disable().unwrap();
        assert_eq!(win::read().unwrap().enable, Some(0));
        win::write(&before).unwrap();
    }
}
