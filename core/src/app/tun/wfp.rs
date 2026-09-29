// SPDX-License-Identifier: GPL-3.0-or-later
//! Kill switch на Windows (`strict_route`): стойкие фильтры Windows
//! Filtering Platform (WFP), как у WireGuard («block untunneled traffic»)
//! и Mullvad.
//!
//! В своём подслое WFP (наивысший вес) на уровнях ALE connect/recv-accept
//! для IPv4 и IPv6:
//!
//! | вес | фильтр |
//! |---|---|
//! | 15 | разрешить сам клиент (по его exe: соединения к серверу, `direct`, DNS) |
//! | 14 | разрешить loopback |
//! | 13 | разрешить всё через интерфейс TUN |
//! | 12 | разрешить `route_exclude`; DHCP (UDP 67/68), для IPv6 — ICMPv6 (NDP), DHCPv6 и link-local |
//! | 0 | запретить остальное |
//!
//! Фильтры стойкие (`FWPM_FILTER_FLAG_PERSISTENT`): переживают аварийное
//! завершение клиента и даже перезагрузку — пока клиент не запущен снова
//! (он ставит фильтры заново) или не выполнено
//! `reality-client --tun-cleanup`. Интерфейс TUN исчезает вместе с
//! клиентом, поэтому без клиента трафику остаётся только `route_exclude`.
//! Штатное завершение снимает фильтры.
//!
//! Ключи подслоя и фильтров — постоянные GUID: снять можно, ничего не
//! запоминая (и после сбоя, и из другого процесса).

use std::net::IpAddr;
use std::os::windows::ffi::OsStrExt;

use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{
    FWP_E_ALREADY_EXISTS, FWP_E_FILTER_NOT_FOUND, FWP_E_SUBLAYER_NOT_FOUND, HANDLE,
};
use windows_sys::Win32::NetworkManagement::IpHelper::ConvertInterfaceIndexToLuid;
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::*;
use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_WINNT;

use crate::app::access::IpNet;
use crate::error::{Error, Result};

/// Подслой kill switch.
const SUBLAYER: GUID = GUID::from_u128(0x5a1d7c3e_2b4f_4e8a_9c61_7f0e3d2a0000);
/// Ключи фильтров: `FILTER_BASE + номер`.
const FILTER_BASE: u128 = 0x5a1d7c3e_2b4f_4e8a_9c61_7f0e3d2a1000;
/// Сколько ключей перебирать при снятии (с запасом над числом фильтров).
const MAX_FILTERS: u128 = 256;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn check(code: u32, what: &str) -> Result<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(Error::Config(format!(
            "tun: kill switch (WFP): {what}: ошибка 0x{code:08x}"
        )))
    }
}

/// Сессия WFP (не динамическая: объекты переживают её закрытие).
struct Engine(HANDLE);

impl Engine {
    fn open() -> Result<Self> {
        let mut h: HANDLE = std::ptr::null_mut();
        // SAFETY: пустая сессия — обычная (не динамическая); h — место для
        // дескриптора.
        let session: FWPM_SESSION0 = unsafe { std::mem::zeroed() };
        let r = unsafe {
            FwpmEngineOpen0(
                std::ptr::null(),
                RPC_C_AUTHN_WINNT,
                std::ptr::null(),
                &session,
                &mut h,
            )
        };
        check(r, "открыть WFP (нужны права администратора)")?;
        Ok(Engine(h))
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        // SAFETY: дескриптор открыт в `open`.
        unsafe {
            FwpmEngineClose0(self.0);
        }
    }
}

/// Идентификатор приложения WFP для exe этого процесса.
struct AppId(*mut FWP_BYTE_BLOB);

impl AppId {
    fn current() -> Result<Self> {
        let exe = std::env::current_exe()
            .map_err(|e| Error::Config(format!("tun: kill switch: путь к exe: {e}")))?;
        let path: Vec<u16> = exe.as_os_str().encode_wide().chain(Some(0)).collect();
        let mut blob: *mut FWP_BYTE_BLOB = std::ptr::null_mut();
        // SAFETY: строка с нулём в конце; blob освобождается в Drop.
        let r = unsafe { FwpmGetAppIdFromFileName0(path.as_ptr(), &mut blob) };
        check(r, "идентификатор приложения")?;
        Ok(AppId(blob))
    }
}

impl Drop for AppId {
    fn drop(&mut self) {
        // SAFETY: память выделена WFP в `current`.
        unsafe { FwpmFreeMemory0(&mut self.0 as *mut _ as *mut *mut core::ffi::c_void) }
    }
}

/// Номер интерфейса → его LUID (для условия WFP).
fn luid_of(index: u32) -> Result<u64> {
    // SAFETY: luid — место для ответа.
    let mut luid: NET_LUID_LH = unsafe { std::mem::zeroed() };
    let r = unsafe { ConvertInterfaceIndexToLuid(index, &mut luid) };
    check(r, "LUID интерфейса TUN")?;
    // SAFETY: объединение — одно 64-битное значение.
    Ok(unsafe { luid.Value })
}

fn cond_u8(key: GUID, v: u8) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: key,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_UINT8,
            Anonymous: FWP_CONDITION_VALUE0_0 { uint8: v },
        },
    }
}

fn cond_u16(key: GUID, v: u16) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: key,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_UINT16,
            Anonymous: FWP_CONDITION_VALUE0_0 { uint16: v },
        },
    }
}

/// Добавляет фильтры с постоянными ключами по порядку.
struct Adder<'a> {
    engine: &'a Engine,
    next: u128,
}

impl Adder<'_> {
    fn add(
        &mut self,
        layer: GUID,
        weight: u8,
        permit: bool,
        conds: &mut [FWPM_FILTER_CONDITION0],
        name: &str,
    ) -> Result<()> {
        let mut wname = wide(name);
        let key = GUID::from_u128(FILTER_BASE + self.next);
        self.next += 1;
        // SAFETY: всё, на что указывает фильтр (имя, условия и их
        // значения), живёт до конца вызова FwpmFilterAdd0.
        let mut f: FWPM_FILTER0 = unsafe { std::mem::zeroed() };
        f.filterKey = key;
        f.displayData.name = wname.as_mut_ptr();
        f.flags = FWPM_FILTER_FLAG_PERSISTENT;
        f.layerKey = layer;
        f.subLayerKey = SUBLAYER;
        f.weight = FWP_VALUE0 {
            r#type: FWP_UINT8,
            Anonymous: FWP_VALUE0_0 { uint8: weight },
        };
        f.numFilterConditions = conds.len() as u32;
        f.filterCondition = if conds.is_empty() {
            std::ptr::null_mut()
        } else {
            conds.as_mut_ptr()
        };
        f.action.r#type = if permit {
            FWP_ACTION_PERMIT
        } else {
            FWP_ACTION_BLOCK
        };
        let mut id = 0u64;
        let r = unsafe { FwpmFilterAdd0(self.engine.0, &f, std::ptr::null_mut(), &mut id) };
        check(r, &format!("фильтр «{name}»"))
    }
}

/// Включить kill switch: всё, кроме клиента, loopback, TUN (`tun_index`)
/// и `exclude`, запрещено.
pub fn enable(tun_index: u32, exclude: &[IpNet]) -> Result<()> {
    disable()?;
    let luid = luid_of(tun_index)?;
    let app = AppId::current()?;
    let engine = Engine::open()?;
    // SAFETY: дескриптор открыт.
    check(
        unsafe { FwpmTransactionBegin0(engine.0, 0) },
        "начать транзакцию",
    )?;
    let r = add_all(&engine, luid, &app, exclude);
    let end = if r.is_ok() {
        unsafe { FwpmTransactionCommit0(engine.0) }
    } else {
        unsafe { FwpmTransactionAbort0(engine.0) }
    };
    r?;
    check(end, "завершить транзакцию")?;
    tracing::info!("tun: kill switch включён (WFP): мимо туннеля трафик не идёт");
    Ok(())
}

fn add_all(engine: &Engine, luid: u64, app: &AppId, exclude: &[IpNet]) -> Result<()> {
    let mut name = wide("reality-client: kill switch");
    // SAFETY: имя живёт до конца вызова.
    let mut sub: FWPM_SUBLAYER0 = unsafe { std::mem::zeroed() };
    sub.subLayerKey = SUBLAYER;
    sub.displayData.name = name.as_mut_ptr();
    sub.flags = FWPM_SUBLAYER_FLAG_PERSISTENT;
    sub.weight = u16::MAX;
    let r = unsafe { FwpmSubLayerAdd0(engine.0, &sub, std::ptr::null_mut()) };
    if r != FWP_E_ALREADY_EXISTS as u32 {
        check(r, "подслой")?;
    }
    let mut a = Adder { engine, next: 0 };
    let mut luid = luid;
    let layers = [
        (FWPM_LAYER_ALE_AUTH_CONNECT_V4, false),
        (FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, false),
        (FWPM_LAYER_ALE_AUTH_CONNECT_V6, true),
        (FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, true),
    ];
    for (layer, v6) in layers {
        // Сам клиент.
        let mut c = [FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_ALE_APP_ID,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_BYTE_BLOB_TYPE,
                Anonymous: FWP_CONDITION_VALUE0_0 { byteBlob: app.0 },
            },
        }];
        a.add(layer, 15, true, &mut c, "клиент")?;
        // Loopback.
        let mut c = [FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_FLAGS,
            matchType: FWP_MATCH_FLAGS_ALL_SET,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_UINT32,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    uint32: FWP_CONDITION_FLAG_IS_LOOPBACK,
                },
            },
        }];
        a.add(layer, 14, true, &mut c, "loopback")?;
        // Интерфейс TUN.
        let mut c = [FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_IP_LOCAL_INTERFACE,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_UINT64,
                Anonymous: FWP_CONDITION_VALUE0_0 { uint64: &mut luid },
            },
        }];
        a.add(layer, 13, true, &mut c, "TUN")?;
        // route_exclude.
        for n in exclude.iter().filter(|n| n.addr().is_ipv6() == v6) {
            let mut m4;
            let mut m6;
            let value = match n.addr() {
                IpAddr::V4(ip) => {
                    let p = u32::from(n.prefix());
                    m4 = FWP_V4_ADDR_AND_MASK {
                        // WFP: адрес IPv4 — в порядке байт хоста.
                        addr: u32::from(ip),
                        mask: if p == 0 { 0 } else { u32::MAX << (32 - p) },
                    };
                    FWP_CONDITION_VALUE0 {
                        r#type: FWP_V4_ADDR_MASK,
                        Anonymous: FWP_CONDITION_VALUE0_0 {
                            v4AddrMask: &mut m4,
                        },
                    }
                }
                IpAddr::V6(ip) => {
                    m6 = FWP_V6_ADDR_AND_MASK {
                        addr: ip.octets(),
                        prefixLength: n.prefix(),
                    };
                    FWP_CONDITION_VALUE0 {
                        r#type: FWP_V6_ADDR_MASK,
                        Anonymous: FWP_CONDITION_VALUE0_0 {
                            v6AddrMask: &mut m6,
                        },
                    }
                }
            };
            let mut c = [FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: value,
            }];
            a.add(layer, 12, true, &mut c, "route_exclude")?;
        }
        // Служебное, без чего пропадает сама сеть: DHCP; для IPv6 — NDP
        // (ICMPv6), DHCPv6 и link-local.
        if !v6 {
            let mut c = [
                cond_u8(FWPM_CONDITION_IP_PROTOCOL, 17),
                cond_u16(FWPM_CONDITION_IP_REMOTE_PORT, 67),
            ];
            a.add(layer, 12, true, &mut c, "DHCP")?;
            let mut c = [
                cond_u8(FWPM_CONDITION_IP_PROTOCOL, 17),
                cond_u16(FWPM_CONDITION_IP_LOCAL_PORT, 68),
            ];
            a.add(layer, 12, true, &mut c, "DHCP")?;
        } else {
            let mut c = [cond_u8(FWPM_CONDITION_IP_PROTOCOL, 58)];
            a.add(layer, 12, true, &mut c, "ICMPv6")?;
            let mut c = [
                cond_u8(FWPM_CONDITION_IP_PROTOCOL, 17),
                cond_u16(FWPM_CONDITION_IP_REMOTE_PORT, 547),
            ];
            a.add(layer, 12, true, &mut c, "DHCPv6")?;
            let mut ll = FWP_V6_ADDR_AND_MASK {
                addr: "fe80::".parse::<std::net::Ipv6Addr>().unwrap().octets(),
                prefixLength: 10,
            };
            let mut c = [FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_V6_ADDR_MASK,
                    Anonymous: FWP_CONDITION_VALUE0_0 {
                        v6AddrMask: &mut ll,
                    },
                },
            }];
            a.add(layer, 12, true, &mut c, "link-local")?;
        }
        // Остальное — запретить.
        a.add(layer, 0, false, &mut [], "запретить остальное")?;
    }
    Ok(())
}

/// Снять kill switch (фильтры и подслой); нечего снимать — не ошибка.
pub fn disable() -> Result<()> {
    let engine = Engine::open()?;
    let mut removed = 0;
    for i in 0..MAX_FILTERS {
        let key = GUID::from_u128(FILTER_BASE + i);
        // SAFETY: дескриптор открыт, ключ — на стеке.
        let r = unsafe { FwpmFilterDeleteByKey0(engine.0, &key) };
        if r == 0 {
            removed += 1;
        } else if r != FWP_E_FILTER_NOT_FOUND as u32 {
            check(r, "снять фильтр")?;
        }
    }
    let r = unsafe { FwpmSubLayerDeleteByKey0(engine.0, &SUBLAYER) };
    if r != 0 && r != FWP_E_SUBLAYER_NOT_FOUND as u32 {
        check(r, "снять подслой")?;
    }
    if removed > 0 {
        tracing::info!(filters = removed, "tun: kill switch снят");
    }
    Ok(())
}
