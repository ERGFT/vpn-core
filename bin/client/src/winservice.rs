// SPDX-License-Identifier: GPL-3.0-or-later
//! Windows: служба (автозапуск до входа в систему — для TUN) и автозапуск
//! при входе пользователя (для `--system-proxy`).
//!
//! Служба работает от SYSTEM, поэтому её файлы настроек не должны быть
//! доступны на запись обычным пользователям: иначе любой процесс
//! пользователя мог бы через настройки заставить службу читать и писать
//! файлы от имени SYSTEM. `--service-install` копирует файл настроек и
//! файлы, на которые он ссылается, в `%ProgramData%\RealityClient`, где
//! запись разрешена только SYSTEM и администраторам, и запускает службу
//! на этой копии.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept,
    ServiceErrorControl, ServiceExitCode, ServiceFailureActions, ServiceFailureResetPeriod,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_dispatcher;
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

use reality_core::app::config::Config;

pub const SERVICE_NAME: &str = "RealityClient";
const DISPLAY_NAME: &str = "Reality Client";
const DATA_DIR: &str = "RealityClient";
/// Запись — только SYSTEM и администраторам, наследуется вложенными
/// файлами; унаследованные сверху разрешения отключены (`P`).
const DATA_DIR_SDDL: &str = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";

/// Папка службы: `%ProgramData%\RealityClient`.
pub fn data_dir() -> Result<PathBuf> {
    let base = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
    Ok(base.join(DATA_DIR))
}

// ── запуск как служба ──

type RunFn = Box<dyn FnOnce(tokio::sync::oneshot::Receiver<()>) -> Result<()> + Send>;
static RUN: Mutex<Option<RunFn>> = Mutex::new(None);

windows_service::define_windows_service!(ffi_service_main, service_main);

/// Отдать управление диспетчеру служб; `run` получает сигнал остановки
/// и работает, пока он не придёт.
pub fn run_as_service<F>(run: F) -> Result<()>
where
    F: FnOnce(tokio::sync::oneshot::Receiver<()>) -> Result<()> + Send + 'static,
{
    *RUN.lock().unwrap() = Some(Box::new(run));
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .context("запуск службы (эта команда — для диспетчера служб, не для ручного запуска)")?;
    Ok(())
}

fn service_main(_args: Vec<OsString>) {
    if let Err(e) = service_body() {
        tracing::error!(error = %e, "служба завершилась с ошибкой");
    }
}

fn service_body() -> Result<()> {
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
    let stop_tx = std::sync::Mutex::new(Some(stop_tx));
    let handle = service_control_handler::register(SERVICE_NAME, move |c| match c {
        ServiceControl::Stop | ServiceControl::Shutdown | ServiceControl::Preshutdown => {
            if let Some(tx) = stop_tx.lock().unwrap().take() {
                let _ = tx.send(());
            }
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    })?;
    let status = |state, code: u32| ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: if state == ServiceState::Running {
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
        } else {
            ServiceControlAccept::empty()
        },
        exit_code: ServiceExitCode::Win32(code),
        checkpoint: 0,
        wait_hint: Duration::from_secs(10),
        process_id: None,
    };
    handle.set_service_status(status(ServiceState::Running, 0))?;
    let run = RUN.lock().unwrap().take().expect("задано в run_as_service");
    let r = run(stop_rx);
    // Код 1 (ERROR_INVALID_FUNCTION) — «служба завершилась с ошибкой»:
    // диспетчер перезапустит её по настройкам восстановления.
    let code = if r.is_ok() { 0 } else { 1 };
    if let Err(e) = &r {
        tracing::error!(error = %e, "служба остановлена из-за ошибки");
    }
    handle.set_service_status(status(ServiceState::Stopped, code))?;
    r
}

// ── установка и удаление ──

/// Установить (или обновить) службу: скопировать настройки в папку
/// службы и запустить её.
pub fn install(config: &Path) -> Result<()> {
    let cfg =
        Config::load(config).with_context(|| format!("файл настроек {}", config.display()))?;
    reality_core::app::App::build(&cfg).context("настройки не прошли проверку")?;
    let dir = data_dir()?;
    prepare_dir(&dir)?;

    // Служба на ходу держит свой exe и файлы — сначала остановить.
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .context("нет доступа к диспетчеру служб — запустите от имени администратора")?;
    let access = ServiceAccess::QUERY_STATUS
        | ServiceAccess::START
        | ServiceAccess::STOP
        | ServiceAccess::CHANGE_CONFIG;
    let existing = manager.open_service(SERVICE_NAME, access).ok();
    if let Some(s) = &existing {
        stop_and_wait(s)?;
    }

    let src_dir = config
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
        .canonicalize()?;
    let config_abs = config.canonicalize()?;
    let dir_abs = dir.canonicalize()?;
    let dst_config = if src_dir == dir_abs {
        config_abs.clone()
    } else {
        dir.join("client.toml")
    };
    if src_dir != dir_abs {
        let mut files = vec![config_abs.clone()];
        files.extend(cfg.input_files());
        for f in files {
            let f = match f.canonicalize() {
                Ok(f) => f,
                Err(_) => continue, // необязательный файл, которого нет
            };
            let rel = f.strip_prefix(&src_dir).map_err(|_| {
                anyhow::anyhow!(
                    "{} лежит вне папки файла настроек ({}) — служба копирует только \
                     файлы из этой папки; положите его рядом и укажите относительный путь",
                    f.display(),
                    src_dir.display()
                )
            })?;
            let dst = if f == config_abs {
                dst_config.clone()
            } else {
                dir.join(rel)
            };
            // Вложенные папки — с теми же правами.
            let mut sub = dir.clone();
            if let Some(parent) = rel.parent() {
                for part in parent.components() {
                    sub.push(part);
                    prepare_dir(&sub)?;
                }
            }
            fresh_copy(&f, &dst)?;
            println!("скопирован {}", rel.display());
        }
    }

    // Сам клиент (и wintun.dll для TUN) — тоже в закрытую папку: exe
    // службы в папке пользователя тот мог бы подменить и получить SYSTEM.
    let src_exe = std::env::current_exe()?.canonicalize()?;
    let exe = dir.join("reality-client.exe");
    if src_exe.parent() != Some(dir_abs.as_path()) {
        fresh_copy(&src_exe, &exe)?;
        let wintun = src_exe.with_file_name("wintun.dll");
        if wintun.is_file() {
            fresh_copy(&wintun, &dir.join("wintun.dll"))?;
        }
    }

    let info = ServiceInfo {
        name: SERVICE_NAME.into(),
        display_name: DISPLAY_NAME.into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe,
        launch_arguments: vec![
            "--service".into(),
            "--config".into(),
            dst_config.clone().into(),
            "--log-file".into(),
            dir.join("reality-client.log").into(),
        ],
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    };
    let service = match existing {
        Some(s) => {
            s.change_config(&info)?;
            println!("служба {SERVICE_NAME} обновлена");
            s
        }
        None => {
            let s = manager.create_service(&info, access)?;
            println!("служба {SERVICE_NAME} установлена");
            s
        }
    };
    let _ = service.set_description(
        "VLESS/REALITY-клиент (reality-core): настройки — %ProgramData%\\RealityClient\\client.toml",
    );
    // Перезапуск после сбоя: 5 с, 30 с, 2 мин. Не удалось (старые системы,
    // Wine) — служба работает и без этого.
    let restart = service.update_failure_actions(ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86400)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![
            ServiceAction {
                action_type: ServiceActionType::Restart,
                delay: Duration::from_secs(5),
            },
            ServiceAction {
                action_type: ServiceActionType::Restart,
                delay: Duration::from_secs(30),
            },
            ServiceAction {
                action_type: ServiceActionType::Restart,
                delay: Duration::from_secs(120),
            },
        ]),
    });
    if let Err(e) = restart.and_then(|_| service.set_failure_actions_on_non_crash_failures(true)) {
        eprintln!("предупреждение: перезапуск службы после сбоя не настроен: {e}");
    }
    service.start::<&str>(&[]).context("запуск службы")?;
    println!(
        "служба запущена; настройки — {}, журнал — {}",
        dst_config.display(),
        dir.join("reality-client.log").display()
    );
    Ok(())
}

fn stop_and_wait(s: &windows_service::service::Service) -> Result<()> {
    if s.query_status()?.current_state == ServiceState::Stopped {
        return Ok(());
    }
    let _ = s.stop();
    for _ in 0..100 {
        if s.query_status()?.current_state == ServiceState::Stopped {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    bail!("служба {SERVICE_NAME} не остановилась за 10 с")
}

/// Остановить и удалить службу; папка с настройками остаётся.
pub fn uninstall() -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .context("нет доступа к диспетчеру служб — запустите от имени администратора")?;
    let s = manager
        .open_service(
            SERVICE_NAME,
            ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
        )
        .with_context(|| format!("служба {SERVICE_NAME} не установлена"))?;
    stop_and_wait(&s)?;
    s.delete()?;
    println!(
        "служба {SERVICE_NAME} удалена; настройки остались в {}",
        data_dir()?.display()
    );
    Ok(())
}

/// Папка, куда писать могут только SYSTEM и администраторы: новая
/// создаётся сразу с такими правами (без промежутка, когда в неё может
/// что-то положить пользователь); существующая должна принадлежать
/// администраторам или SYSTEM (папку в ProgramData может заранее создать
/// любой пользователь — тогда он её владелец и вернул бы себе права), её
/// права переписываются.
fn prepare_dir(dir: &Path) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{LocalFree, ERROR_ALREADY_EXISTS, ERROR_SUCCESS};
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW,
        SetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        GetSecurityDescriptorDacl, IsWellKnownSid, WinBuiltinAdministratorsSid, WinLocalSystemSid,
        DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
    };
    use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;

    struct Sd(PSECURITY_DESCRIPTOR);
    impl Drop for Sd {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: выделено функциями Windows через LocalAlloc.
                unsafe { LocalFree(self.0 as _) };
            }
        }
    }
    let os_err = |what: &str, e: std::io::Error| anyhow::anyhow!("{what} {}: {e}", dir.display());
    let sddl: Vec<u16> = DATA_DIR_SDDL.encode_utf16().chain([0]).collect();
    let path: Vec<u16> = dir.as_os_str().encode_wide().chain([0]).collect();
    let mut sd = Sd(std::ptr::null_mut());
    // SAFETY: строки с нулём в конце; sd освобождается в Drop.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut sd.0,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(os_err("права папки", std::io::Error::last_os_error()));
    }
    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0,
        bInheritHandle: 0,
    };
    // SAFETY: путь с нулём в конце, sa живёт до конца вызова.
    if unsafe { CreateDirectoryW(path.as_ptr(), &sa) } != 0 {
        return Ok(());
    }
    let e = std::io::Error::last_os_error();
    if e.raw_os_error() != Some(ERROR_ALREADY_EXISTS as i32) {
        return Err(os_err("не удалось создать папку", e));
    }
    if !dir.is_dir() || dir.symlink_metadata()?.file_type().is_symlink() {
        bail!(
            "{} — не папка (или ссылка): удалите и повторите",
            dir.display()
        );
    }
    // Владелец существующей папки.
    let mut owner: PSID = std::ptr::null_mut();
    let mut osd = Sd(std::ptr::null_mut());
    // SAFETY: выходные указатели; osd освобождается в Drop, owner указывает внутрь osd.
    let r = unsafe {
        GetNamedSecurityInfoW(
            path.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut osd.0,
        )
    };
    if r != ERROR_SUCCESS {
        return Err(os_err(
            "не удалось узнать владельца",
            std::io::Error::from_raw_os_error(r as i32),
        ));
    }
    // SAFETY: owner — SID из osd.
    let trusted = unsafe {
        IsWellKnownSid(owner, WinBuiltinAdministratorsSid) != 0
            || IsWellKnownSid(owner, WinLocalSystemSid) != 0
    };
    if !trusted {
        bail!(
            "папку {} создал не администратор — её содержимому службе доверять нельзя; \
             удалите папку и повторите --service-install",
            dir.display()
        );
    }
    let mut present = 0;
    let mut defaulted = 0;
    let mut dacl = std::ptr::null_mut();
    // SAFETY: sd — корректный дескриптор из ConvertString….
    if unsafe { GetSecurityDescriptorDacl(sd.0, &mut present, &mut dacl, &mut defaulted) } == 0 {
        return Err(os_err("права папки", std::io::Error::last_os_error()));
    }
    // SAFETY: путь с нулём в конце, dacl указывает внутрь sd.
    let r = unsafe {
        SetNamedSecurityInfoW(
            path.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            dacl,
            std::ptr::null_mut(),
        )
    };
    if r != ERROR_SUCCESS {
        return Err(os_err(
            "не удалось закрыть от записи пользователями папку",
            std::io::Error::from_raw_os_error(r as i32),
        ));
    }
    Ok(())
}

/// Скопировать файл в папку службы заново: прежний файл (или подложенная
/// на его месте ссылка) удаляется, новый наследует права папки.
fn fresh_copy(src: &Path, dst: &Path) -> Result<()> {
    match std::fs::remove_file(dst) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(anyhow::anyhow!("удалить старый {}: {e}", dst.display())),
    }
    std::fs::copy(src, dst)
        .with_context(|| format!("скопировать {} в {}", src.display(), dst.display()))?;
    Ok(())
}

// ── автозапуск при входе пользователя ──

/// Добавить запуск при входе в систему (HKCU\...\Run): без окна, журнал
/// — рядом с файлом настроек.
pub fn autostart_install(config: &Path, system_proxy: bool) -> Result<()> {
    let cfg_abs = config
        .canonicalize()
        .with_context(|| format!("файл настроек {}", config.display()))?;
    Config::load(&cfg_abs)
        .and_then(|c| reality_core::app::App::build(&c).map(|_| ()))
        .context("настройки не прошли проверку")?;
    let log = cfg_abs.with_file_name("reality-client.log");
    let exe = std::env::current_exe()?;
    let mut cmd = format!(
        "\"{}\" --config \"{}\" --log-file \"{}\" --hide-console",
        strip_verbatim(&exe),
        strip_verbatim(&cfg_abs),
        strip_verbatim(&log)
    );
    if system_proxy {
        cmd.push_str(" --system-proxy");
    }
    crate::sysproxy::set_user_string(RUN_KEY, SERVICE_NAME, Some(&cmd))?;
    println!("автозапуск при входе включён: {cmd}");
    Ok(())
}

pub fn autostart_uninstall() -> Result<()> {
    crate::sysproxy::set_user_string(RUN_KEY, SERVICE_NAME, None)?;
    println!("автозапуск при входе выключен");
    Ok(())
}

/// `\\?\C:\x` (так пишет canonicalize) → `C:\x`: такие пути не все
/// программы понимают.
fn strip_verbatim(p: &Path) -> String {
    let s = p.display().to_string();
    s.strip_prefix(r"\\?\").map(str::to_string).unwrap_or(s)
}

/// Отцепиться от окна консоли (запуск из автозапуска — без окна).
pub fn hide_console() {
    unsafe {
        windows_sys::Win32::System::Console::FreeConsole();
    }
}
