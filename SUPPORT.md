[Русский](#помощь) | [English](#support)

# Помощь

- **Как собрать, запустить и настроить** — [README.md](README.md)
  (быстрый старт) и [docs/](docs/README.md): ключи командной строки, файл
  настроек, TUN, DNS, подписки; Windows —
  [docs/WINDOWS.md](docs/WINDOWS.md). Проверить файл настроек, ничего не
  запуская: `reality-client --config config.json --check`.
- **Не подключается** — запустите с `RUST_LOG=debug` и посмотрите
  журнал; сверьте параметры ссылки с [docs/LINK.md](docs/LINK.md) и
  ограничения — с [docs/FEATURES.md](docs/FEATURES.md) (например, `kcp` не
  поддерживается).
- **Нашли ошибку или хотите новую возможность** — откройте
  [issue](https://github.com/ERGFT/vpn-core/issues/new/choose) по
  шаблону. ⚠️ Не публикуйте настоящую ссылку на сервер, UUID, ключи и
  адрес подписки.
- **Уязвимость** — не в issue, а закрыто: [SECURITY.md](SECURITY.md).

Это проект одного человека, отвечаю по мере сил. Вопросы о настройке
самого сервера (Xray-core, панели 3x-ui, Marzban, Remnawave) лучше
задавать в их сообществах.

---


# Support

- **Building, running and configuring** — [README.en.md](README.en.md)
  (quick start) and [docs/](docs/README.en.md): command-line flags, config
  file, TUN, DNS, subscriptions; Windows —
  [docs/WINDOWS.en.md](docs/WINDOWS.en.md). To validate a config file
  without starting anything: `reality-client --config config.json --check`.
- **It does not connect** — run with `RUST_LOG=debug` and read the log;
  check the link parameters against [docs/LINK.en.md](docs/LINK.en.md) and
  the limitations in [docs/FEATURES.en.md](docs/FEATURES.en.md) (for example,
  `kcp` is not supported).
- **Found a bug or want a feature** — open an
  [issue](https://github.com/ERGFT/vpn-core/issues/new/choose) using a
  template. ⚠️ Do not post your real server link, UUID, keys or
  subscription URL.
- **Vulnerability** — not in an issue, report it privately:
  [SECURITY.md](SECURITY.md#security).

This is a one-person project; answers come as time permits. Questions about
setting up the server itself (Xray-core, the 3x-ui, Marzban, Remnawave
panels) are better asked in their communities.
