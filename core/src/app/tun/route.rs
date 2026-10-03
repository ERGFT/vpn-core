// SPDX-License-Identifier: GPL-3.0-or-later
//! `auto_route`: направить трафик компьютера в TUN и вернуть как было.
//!
//! Linux (как у sing-box): своя таблица маршрутов с маршрутом по
//! умолчанию через TUN и два правила —
//! `fwmark 0x7e2 → main` (соединения самого клиента, помеченные
//! [`crate::net_protect`], идут обычным путём) и `всё остальное → таблица
//! TUN`. Подсети из `route_exclude` — правила `to … lookup main`. Если
//! клиент убит, интерфейс исчезает вместе со своими маршрутами, таблица
//! пустеет, и трафик снова идёт по main: сеть не «зависает». С
//! `strict_route` (kill switch) после таблицы TUN стоит запрет
//! `unreachable`: убитый клиент оставляет сеть закрытой (кроме
//! `route_exclude`), пока его не запустят снова или не выполнят
//! `reality-client --tun-cleanup`.
//!
//! Свои правила и маршруты помечены протоколом [`PROTO`] (`protocol` у
//! `ip rule`, `proto` у `ip route`), и снимается только помеченное: чужие
//! правила на тех же приоритетах и чужие маршруты в той же таблице не
//! трогаются ни при запуске, ни при выходе, ни в `--tun-cleanup`. Если
//! приоритеты или таблица уже заняты чужими записями, `auto_route` не
//! включается — с ошибкой, где перечислено, что занято.
//!
//! Windows: маршруты `0.0.0.0/1` и `128.0.0.0/1` (и `::/1`, `8000::/1`)
//! через TUN — они точнее маршрута по умолчанию; соединения клиента
//! привязаны к физическому интерфейсу (`IP_UNICAST_IF`). Маршруты живут,
//! пока жив интерфейс. `strict_route` (kill switch) — стойкие фильтры WFP
//! ([`super::wfp`]): убитый клиент так же оставляет сеть закрытой до
//! нового запуска или `--tun-cleanup`.
//!
//! Таблица, приоритеты правил и фильтры WFP у всех экземпляров общие,
//! поэтому `auto_route` на компьютере (Linux — в сетевом пространстве)
//! может держать только один процесс: [`HostLock`]. Второй не запустится,
//! а `--tun-cleanup` не тронет маршруты работающего экземпляра.

use crate::app::access::IpNet;
use crate::error::{Error, Result};
use crate::net_protect;

/// Метка сокетов клиента и номер таблицы маршрутов (Linux).
pub const MARK: u32 = 0x7e2;
pub const TABLE: u32 = 2022;
#[cfg(target_os = "linux")]
const PREF_MARK: u32 = 9000;
#[cfg(target_os = "linux")]
const PREF_TUN: u32 = 9001;
#[cfg(target_os = "linux")]
const PREF_BLOCK: u32 = 9002;
/// Метка своих правил и маршрутов: номер протокола маршрутизации, не
/// занятый в `rt_protos` (метка у правил — с Linux 4.17).
#[cfg(target_os = "linux")]
const PROTO: u8 = 202;

/// Пока жив — трафик идёт в TUN; при уничтожении маршруты снимаются.
pub struct RouteGuard {
    down: Vec<Vec<String>>,
    /// Владение `auto_route`; снимается после маршрутов (поля
    /// уничтожаются после `Drop::drop`).
    _lock: HostLock,
    /// Включён kill switch WFP (Windows).
    #[cfg(windows)]
    wfp: bool,
}

impl Drop for RouteGuard {
    fn drop(&mut self) {
        #[cfg(windows)]
        if self.wfp {
            if let Err(e) = super::wfp::disable() {
                tracing::warn!(error = %e, "tun: kill switch не снят — reality-client --tun-cleanup");
            }
        }
        for cmd in &self.down {
            let _ = run(cmd, true);
        }
        net_protect::set(None);
        tracing::info!("tun: маршруты возвращены");
    }
}

/// Один владелец `auto_route` на компьютер. Держится, пока жив процесс:
/// после аварии ОС снимает её сама, поэтому занятая блокировка всегда
/// означает работающий экземпляр, а свободная — что маршруты и фильтры,
/// если остались, никому не принадлежат.
///
/// Linux — абстрактный сокет Unix: он живёт в сетевом пространстве, как и
/// сами маршруты, и не зависит от прав на файлы (служба с
/// `ProtectSystem=strict`). Windows — файл `auto_route.lock`, открытый без
/// общего доступа, в защищённом каталоге ([`set_lock_dir`]).
pub struct HostLock {
    #[cfg(target_os = "linux")]
    _sock: std::os::unix::net::UnixListener,
    #[cfg(windows)]
    _file: std::fs::File,
}

#[cfg(windows)]
static LOCK_DIR: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();

/// Каталог для файла блокировки `auto_route` на Windows: запись в него —
/// только SYSTEM и администраторам (у клиента — `%ProgramData%\RealityClient`
/// с таким DACL). Задаётся приложением до запуска ядра, один раз; без него
/// `auto_route` на Windows не запускается. На других системах не нужен.
pub fn set_lock_dir(dir: std::path::PathBuf) {
    #[cfg(windows)]
    {
        let _ = LOCK_DIR.set(dir);
    }
    #[cfg(not(windows))]
    let _ = dir;
}

impl HostLock {
    pub fn acquire() -> std::result::Result<HostLock, String> {
        const BUSY: &str = "auto_route уже держит другой запущенный экземпляр reality-client";
        #[cfg(target_os = "linux")]
        {
            use std::os::linux::net::SocketAddrExt;
            use std::os::unix::net::{SocketAddr, UnixListener};
            let addr = SocketAddr::from_abstract_name(b"reality-client/auto_route")
                .map_err(|e| e.to_string())?;
            match UnixListener::bind_addr(&addr) {
                Ok(s) => Ok(HostLock { _sock: s }),
                Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => Err(BUSY.into()),
                Err(e) => Err(format!("блокировка auto_route: {e}")),
            }
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            // ERROR_SHARING_VIOLATION: файл открыт другим процессом.
            const SHARING_VIOLATION: i32 = 32;
            // Только в каталоге, куда пишут лишь SYSTEM и администраторы:
            // в общем %ProgramData% любой пользователь открыл бы файл
            // раньше службы и не дал бы ей запуститься.
            let Some(dir) = LOCK_DIR.get() else {
                return Err("не задан защищённый каталог для блокировки (set_lock_dir)".into());
            };
            let path = dir.join("auto_route.lock");
            match std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .share_mode(0)
                .open(&path)
            {
                Ok(f) => Ok(HostLock { _file: f }),
                Err(e) if e.raw_os_error() == Some(SHARING_VIOLATION) => Err(BUSY.into()),
                Err(e) => Err(format!("блокировка auto_route ({}): {e}", path.display())),
            }
        }
        #[cfg(not(any(target_os = "linux", windows)))]
        {
            Ok(HostLock {})
        }
    }
}

/// Абсолютный путь к системной утилите: служба работает от root/SYSTEM,
/// и поиск по `PATH` дал бы выполнить подложенную программу.
fn tool_path(name: &str) -> std::path::PathBuf {
    #[cfg(windows)]
    {
        let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
        std::path::Path::new(&root)
            .join("System32")
            .join(format!("{name}.exe"))
    }
    #[cfg(not(windows))]
    {
        for dir in ["/usr/sbin", "/sbin", "/usr/bin", "/bin"] {
            let p = std::path::Path::new(dir).join(name);
            if p.exists() {
                return p;
            }
        }
        std::path::PathBuf::from(name) // последний шанс — как раньше
    }
}

fn run(cmd: &[String], quiet: bool) -> Result<()> {
    let out = std::process::Command::new(tool_path(&cmd[0]))
        .args(&cmd[1..])
        .output()
        .map_err(|e| Error::Config(format!("tun: не удалось запустить {}: {e}", cmd[0])))?;
    if !out.status.success() {
        let msg = String::from_utf8_lossy(&out.stderr).trim().to_string();
        if !quiet {
            return Err(Error::Config(format!(
                "tun: команда «{}» не удалась: {msg}",
                cmd.join(" ")
            )));
        }
    }
    Ok(())
}

fn args(s: &str) -> Vec<String> {
    s.split_whitespace().map(str::to_string).collect()
}

/// Включить маршруты. `lock` — владение `auto_route` ([`HostLock`]),
/// `ifname` — имя TUN, `if_index` — его номер (нужен на Windows).
pub fn setup(
    lock: HostLock,
    ifname: &str,
    if_index: Option<u32>,
    v6: bool,
    exclude: &[IpNet],
    strict: bool,
) -> Result<RouteGuard> {
    #[cfg(target_os = "linux")]
    {
        let _ = if_index;
        linux(lock, ifname, v6, exclude, strict)
    }
    #[cfg(windows)]
    {
        windows(lock, ifname, if_index, v6, exclude, strict)
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = (lock, ifname, if_index, v6, exclude, strict);
        Err(Error::Config(
            "tun: auto_route есть только для Linux и Windows".into(),
        ))
    }
}

/// Снять то, что осталось после аварийного завершения: на Linux — правила
/// и таблицу TUN (в том числе блокировку `strict_route`), на Windows —
/// kill switch WFP (маршруты там исчезают вместе с интерфейсом).
pub fn cleanup() -> Result<()> {
    // Живой экземпляр держит блокировку: его маршруты — не остатки.
    let _lock = HostLock::acquire()
        .map_err(|e| Error::Config(format!("--tun-cleanup: {e}; сначала остановите его")))?;
    #[cfg(target_os = "linux")]
    {
        // Только помеченное PROTO: чужие правила и маршруты остаются.
        for cmd in linux_down() {
            let _ = run(&cmd, true);
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        super::wfp::disable()
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        Err(Error::Config(
            "--tun-cleanup нужен только на Linux и Windows".into(),
        ))
    }
}

#[cfg(target_os = "linux")]
fn linux_down() -> Vec<Vec<String>> {
    let mut down = Vec::new();
    for f in ["-4", "-6"] {
        // Правил с одним приоритетом может быть несколько — по одному за раз.
        // С `protocol` ядро удаляет только правило с этой меткой: чужое
        // на том же приоритете остаётся.
        for pref in [PREF_MARK, PREF_TUN, PREF_BLOCK] {
            for _ in 0..16 {
                down.push(args(&format!(
                    "ip {f} rule del pref {pref} protocol {PROTO}"
                )));
            }
        }
        down.push(args(&format!(
            "ip {f} route flush table {TABLE} proto {PROTO}"
        )));
    }
    down
}

/// `ip -N -j <args>` (числа вместо имён протоколов). Нет таблицы или
/// семейства адресов (IPv6 выключен) — пустой список. Иначе ошибка: не
/// узнав, чьи записи, ничего не трогаем.
#[cfg(target_os = "linux")]
fn ip_json(a: &[&str]) -> Result<serde_json::Value> {
    let out = std::process::Command::new(tool_path("ip"))
        .args(["-N", "-j"])
        .args(a)
        .output()
        .map_err(|e| Error::Config(format!("tun: не удалось запустить ip: {e}")))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        if err.contains("does not exist") || err.contains("not supported") {
            return Ok(serde_json::Value::Array(Vec::new()));
        }
        return Err(Error::Config(format!(
            "tun: не удалось проверить правила и маршруты («ip -j {}»): {}",
            a.join(" "),
            err.trim()
        )));
    }
    if out.stdout.iter().all(u8::is_ascii_whitespace) {
        return Ok(serde_json::Value::Array(Vec::new()));
    }
    serde_json::from_slice(&out.stdout).map_err(|e| {
        Error::Config(format!(
            "tun: не удалось разобрать вывод «ip -j {}»: {e}",
            a.join(" ")
        ))
    })
}

/// Помечена ли запись `ip -N -j` нашим протоколом.
#[cfg(target_os = "linux")]
fn is_ours(e: &serde_json::Value) -> bool {
    match e.get("protocol") {
        Some(serde_json::Value::String(p)) => p.parse::<u8>() == Ok(PROTO),
        Some(serde_json::Value::Number(p)) => p.as_u64() == Some(u64::from(PROTO)),
        _ => false,
    }
}

/// Чужие записи: правила на приоритетах `PREF_*` и маршруты таблицы
/// `TABLE` без метки [`PROTO`] (`rules`, `routes` — вывод `ip -N -j`).
#[cfg(target_os = "linux")]
fn foreign_in(f: &str, rules: &serde_json::Value, routes: &serde_json::Value) -> Vec<String> {
    let list = |v: &serde_json::Value| v.as_array().cloned().unwrap_or_default();
    let mut out = Vec::new();
    for r in list(rules) {
        let pref = r.get("priority").and_then(serde_json::Value::as_u64);
        if pref.is_some_and(|p| [PREF_MARK, PREF_TUN, PREF_BLOCK].contains(&(p as u32)))
            && !is_ours(&r)
        {
            out.push(format!("ip {f} rule: {r}"));
        }
    }
    for r in list(routes) {
        if !is_ours(&r) {
            out.push(format!("ip {f} route table {TABLE}: {r}"));
        }
    }
    out
}

/// Чужие правила и маршруты на наших приоритетах и в нашей таблице.
#[cfg(target_os = "linux")]
fn foreign_entries(fams: &[&str]) -> Result<Vec<String>> {
    let table = TABLE.to_string();
    let mut out = Vec::new();
    for f in fams {
        let rules = ip_json(&[f, "rule", "show"])?;
        let routes = ip_json(&[f, "route", "show", "table", &table])?;
        out.extend(foreign_in(f, &rules, &routes));
    }
    Ok(out)
}

#[cfg(target_os = "linux")]
fn linux(
    lock: HostLock,
    ifname: &str,
    v6: bool,
    exclude: &[IpNet],
    strict: bool,
) -> Result<RouteGuard> {
    let fams: Vec<&str> = if v6 { vec!["-4", "-6"] } else { vec!["-4"] };
    // Приоритеты и таблица общие для всех программ: занятые чужими
    // записями — не наши, и смешивать с ними свои нельзя.
    let foreign = foreign_entries(&fams)?;
    if !foreign.is_empty() {
        return Err(Error::Config(format!(
            "tun: приоритеты правил {PREF_MARK}–{PREF_BLOCK} или таблица маршрутов \
             {TABLE} уже заняты другой программой — auto_route не включён, чужие \
             записи не тронуты:\n  {}\nЕсли это остатки старой версии \
             reality-client (без метки protocol {PROTO}), удалите их вручную: \
             ip rule del pref <приоритет>; ip route flush table {TABLE}",
            foreign.join("\n  ")
        )));
    }
    let down = linux_down();
    // Свои остатки прошлого запуска (если его убили) — убрать.
    for cmd in &down {
        let _ = run(cmd, true);
    }
    // Метка — раньше правил: иначе первые же соединения клиента ушли бы в TUN.
    net_protect::set(Some(net_protect::Protect::Mark(MARK)));
    let guard = RouteGuard { down, _lock: lock };
    let mut up = Vec::new();
    for f in &fams {
        up.push(args(&format!(
            "ip {f} route replace default dev {ifname} table {TABLE} proto {PROTO}"
        )));
        up.push(args(&format!(
            "ip {f} rule add pref {PREF_MARK} fwmark {MARK:#x} lookup main protocol {PROTO}"
        )));
    }
    // Исключения — правилом в main (а не throw в таблице TUN): так они
    // работают и при strict_route.
    for n in exclude {
        let f = if n.addr().is_ipv4() { "-4" } else { "-6" };
        if f == "-6" && !v6 {
            continue;
        }
        up.push(args(&format!(
            "ip {f} rule add pref {PREF_MARK} to {}/{} lookup main protocol {PROTO}",
            n.addr(),
            n.prefix()
        )));
    }
    for f in &fams {
        up.push(args(&format!(
            "ip {f} rule add pref {PREF_TUN} lookup {TABLE} protocol {PROTO}"
        )));
        if strict {
            // Kill switch: если TUN пропал (клиент убит), таблица пуста —
            // и этот запрет не пускает трафик мимо туннеля.
            up.push(args(&format!(
                "ip {f} rule add pref {PREF_BLOCK} unreachable protocol {PROTO}"
            )));
        }
    }
    for cmd in &up {
        // Ошибка — guard при выходе снимет то, что успели добавить.
        run(cmd, false)?;
    }
    tracing::info!(
        interface = ifname,
        strict,
        "tun: весь трафик направлен в TUN"
    );
    Ok(guard)
}

#[cfg(windows)]
fn windows(
    lock: HostLock,
    ifname: &str,
    if_index: Option<u32>,
    v6: bool,
    exclude: &[IpNet],
    strict: bool,
) -> Result<RouteGuard> {
    use std::net::IpAddr;
    let idx = if_index.ok_or_else(|| Error::Config("tun: не известен номер интерфейса".into()))?;
    let phys4 = winapi::best_interface(IpAddr::from([1, 1, 1, 1])).ok_or_else(|| {
        Error::Config("tun: не найден физический интерфейс с выходом в интернет".into())
    })?;
    let phys6 = winapi::best_interface(IpAddr::from([
        0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111u16,
    ]));
    net_protect::set(Some(net_protect::Protect::Interface {
        v4: phys4,
        v6: phys6,
    }));
    // Без IPv6 у физического интерфейса IPv6 в TUN не направляется: иначе
    // система считала бы IPv6 рабочим, программы шли бы на AAAA-адреса, а
    // выход `direct` их никуда не донёс бы. Без маршрута программа сразу
    // получает «сеть недоступна» и переходит на IPv4.
    let v6 = v6 && phys6.is_some();
    if !v6 {
        tracing::info!("tun: у компьютера нет IPv6 — IPv6 в TUN не направляется");
    }
    let mut prefixes = vec![("ipv4", "0.0.0.0/1"), ("ipv4", "128.0.0.0/1")];
    if v6 {
        prefixes.push(("ipv6", "::/1"));
        prefixes.push(("ipv6", "8000::/1"));
    }
    let mut down = Vec::new();
    let mut up = Vec::new();
    for (fam, p) in &prefixes {
        up.push(args(&format!(
            "netsh interface {fam} add route prefix={p} interface={idx} metric=1 store=active"
        )));
        down.push(args(&format!(
            "netsh interface {fam} delete route prefix={p} interface={idx} store=active"
        )));
    }
    // Исключения — через шлюз физического интерфейса.
    if let Some(gw) = winapi::gateway_v4(phys4) {
        for n in exclude.iter().filter(|n| n.addr().is_ipv4()) {
            let p = format!("{}/{}", n.addr(), n.prefix());
            up.push(args(&format!(
                "netsh interface ipv4 add route prefix={p} interface={phys4} nexthop={gw} store=active"
            )));
            down.push(args(&format!(
                "netsh interface ipv4 delete route prefix={p} interface={phys4} nexthop={gw} store=active"
            )));
        }
    } else if !exclude.is_empty() {
        tracing::warn!("tun: шлюз не найден — route_exclude не применён");
    }
    if exclude.iter().any(|n| n.addr().is_ipv6()) {
        tracing::warn!("tun: route_exclude для IPv6 на Windows пока не поддерживается");
    }
    let mut guard = RouteGuard {
        down,
        _lock: lock,
        wfp: false,
    };
    for cmd in &up {
        run(cmd, false)?;
    }
    if strict {
        super::wfp::enable(idx, exclude)?;
        guard.wfp = true;
    }
    // Кеш DNS-клиента Windows мог запомнить неудачи, пока интерфейс
    // поднимался; теперь все запросы идут через TUN — начать с чистого.
    let _ = run(&args("ipconfig /flushdns"), true);
    tracing::info!(interface = ifname, "tun: весь трафик направлен в TUN");
    Ok(guard)
}

#[cfg(windows)]
mod winapi {
    use std::net::{IpAddr, Ipv4Addr};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetBestInterfaceEx, GetBestRoute, MIB_IPFORWARDROW,
    };
    use windows_sys::Win32::Networking::WinSock::{
        AF_INET, AF_INET6, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6,
    };

    /// Интерфейс, через который система пошла бы к `ip`.
    pub fn best_interface(ip: IpAddr) -> Option<u32> {
        let mut idx = 0u32;
        // SAFETY: структура адреса нужного размера, idx — место для ответа.
        let r = unsafe {
            match ip {
                IpAddr::V4(v4) => {
                    let mut sa: SOCKADDR_IN = std::mem::zeroed();
                    sa.sin_family = AF_INET;
                    sa.sin_addr.S_un.S_addr = u32::from_ne_bytes(v4.octets());
                    GetBestInterfaceEx(&sa as *const _ as *const SOCKADDR, &mut idx)
                }
                IpAddr::V6(v6) => {
                    let mut sa: SOCKADDR_IN6 = std::mem::zeroed();
                    sa.sin6_family = AF_INET6;
                    sa.sin6_addr.u.Byte = v6.octets();
                    GetBestInterfaceEx(&sa as *const _ as *const SOCKADDR, &mut idx)
                }
            }
        };
        (r == 0).then_some(idx)
    }

    /// Шлюз по умолчанию интерфейса `idx` (IPv4).
    pub fn gateway_v4(idx: u32) -> Option<Ipv4Addr> {
        let mut row: MIB_IPFORWARDROW = unsafe { std::mem::zeroed() };
        let dst = u32::from_ne_bytes([1, 1, 1, 1]);
        // SAFETY: row — место для ответа.
        let r = unsafe { GetBestRoute(dst, 0, &mut row) };
        if r != 0 || row.dwForwardIfIndex != idx {
            return None;
        }
        let gw = Ipv4Addr::from(row.dwForwardNextHop.to_ne_bytes());
        (!gw.is_unspecified()).then_some(gw)
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::{foreign_in, linux_down, tool_path, HostLock};

    #[test]
    fn tools_by_absolute_path() {
        let ip = tool_path("ip");
        assert!(ip.is_absolute(), "{}", ip.display());
        assert!(ip.ends_with("ip"));
    }

    #[test]
    fn host_lock_is_exclusive() {
        let first = HostLock::acquire().expect("свободна");
        assert!(HostLock::acquire().is_err(), "второй владелец");
        drop(first);
        HostLock::acquire().expect("свободна снова");
    }

    #[test]
    fn foreign_rules_and_routes_are_found() {
        // Вывод `ip -N -j rule show` и `ip -N -j route show table 2022`.
        let rules: serde_json::Value = serde_json::from_str(
            r#"[{"priority":0,"src":"all","table":"local"},
                {"priority":9000,"src":"all","fwmark":"0x7e2","table":"main","protocol":"202"},
                {"priority":9001,"src":"all","table":"2022","protocol":"202"},
                {"priority":9001,"src":"all","table":"100"},
                {"priority":9002,"src":"all","action":"unreachable","protocol":"16"},
                {"priority":9500,"src":"all","table":"200"},
                {"priority":32766,"src":"all","table":"main"}]"#,
        )
        .unwrap();
        let routes: serde_json::Value = serde_json::from_str(
            r#"[{"dst":"default","dev":"rtun0","protocol":"202","scope":"253"},
                {"dst":"10.8.0.0/16","dev":"lo","scope":"253"},
                {"dst":"10.7.0.0/16","dev":"lo","protocol":"4","scope":"253"}]"#,
        )
        .unwrap();
        let f = foreign_in("-4", &rules, &routes);
        assert_eq!(f.len(), 4, "{f:#?}");
        assert!(
            f[0].contains(r#""table":"100""#),
            "чужое на нашем приоритете"
        );
        assert!(f[1].contains(r#""protocol":"16""#), "чужая метка");
        assert!(f[2].contains("10.8.0.0/16") && f[3].contains("10.7.0.0/16"));
        // Только свои — чужого нет; пусто — тоже.
        let ours: serde_json::Value =
            serde_json::from_str(r#"[{"priority":9001,"table":"2022","protocol":"202"}]"#).unwrap();
        assert!(foreign_in("-4", &ours, &serde_json::json!([])).is_empty());
    }

    #[test]
    fn cleanup_removes_only_marked_entries() {
        for cmd in linux_down() {
            let c = cmd.join(" ");
            assert!(
                c.ends_with("protocol 202") || c.ends_with("proto 202"),
                "без метки снялось бы чужое: {c}"
            );
        }
    }
}
