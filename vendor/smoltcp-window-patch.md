# smoltcp 0.12.0 с бэкпортом из 0.13

Стек входа TUN — smoltcp через netstack-smoltcp 0.2.4, которому нужен
smoltcp 0.12. В 0.12 сегмент TCP принимался, если помещался в весь буфер
приёма, а не в объявленное собеседнику окно. Когда окно после
масштабирования (window scale) объявлено нулевым, а в буфере ещё есть
несколько байт, такие данные принимались, и следующий расчёт окна
(`last_scaled_window`) падал паникой «attempt to subtract sequence numbers
with underflow» — стек TUN останавливался (так упал `scripts/tun_netns.sh`
в CI на передаче 2 МиБ).

Правка — та же, что в smoltcp 0.13 ([#1079], «Reject bytes outside the
receive window»): правый край окна — `remote_last_ack + объявленное окно`.
Плюс тест `test_established_rejects_data_beyond_advertised_window`, который
без правки воспроизводит панику. Весь объём — `smoltcp-window-patch.diff`
(`scripts/vendor_patch.sh smoltcp`, проверка — `--check` в
`scripts/ci.sh`).

Обновиться на smoltcp ≥ 0.13 нельзя: ему нужен Rust 1.91 (MSRV проекта —
1.89), а netstack-smoltcp пока требует 0.12. Когда netstack-smoltcp
перейдёт на новую версию, патч убрать (`[patch.crates-io]` в `Cargo.toml`).

`cargo audit`/`cargo deny` не видят крейты из `vendor/`: уязвимости
smoltcp 0.12 смотреть вручную в RustSec.

[#1079]: https://github.com/smoltcp-rs/smoltcp/pull/1079
