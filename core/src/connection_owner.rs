// SPDX-License-Identifier: GPL-3.0-or-later
//! UID владельца TUN-соединения предоставляет приложение, а не удалённый клиент.

use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use crate::app::Network;

/// Получить UID по исходной паре адресов до fake-IP/sniffing.
/// `None` — ОС не смогла установить владельца. Обратный вызов не должен блокировать.
pub type OwnerFn = dyn Fn(Network, SocketAddr, SocketAddr) -> Option<u32> + Send + Sync;

static OWNER: RwLock<Option<Arc<OwnerFn>>> = RwLock::new(None);

/// Установить до запуска TUN; снять после остановки всех ядер процесса.
/// Замыкание может вызываться одновременно из нескольких рабочих потоков.
pub fn set_callback(callback: Option<Arc<OwnerFn>>) {
    *OWNER
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = callback;
}

/// Один запрос на новый TCP/UDP-поток; отрицательного/бессрочного кеша нет.
pub fn resolve(network: Network, source: SocketAddr, destination: SocketAddr) -> Option<u32> {
    let callback = OWNER
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    callback.and_then(|callback| callback(network, source, destination))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn callback_gets_original_ipv4_ipv6_tuple_and_can_be_removed() {
        set_callback(None);
        let src: SocketAddr = "[fd00::2]:32100".parse().unwrap();
        let dst: SocketAddr = "[fd00::3]:443".parse().unwrap();
        assert_eq!(resolve(Network::Tcp, src, dst), None);
        set_callback(Some(Arc::new(move |network, source, destination| {
            assert_eq!(source, src);
            assert_eq!(destination, dst);
            assert_eq!(network, Network::Udp);
            Some(10001)
        })));
        assert_eq!(resolve(Network::Udp, src, dst), Some(10001));
        set_callback(Some(Arc::new(|_, _, _| None)));
        assert_eq!(
            resolve(
                Network::Tcp,
                "192.0.2.2:1234".parse().unwrap(),
                "198.18.0.1:443".parse().unwrap()
            ),
            None
        );
        set_callback(None);
    }
}
