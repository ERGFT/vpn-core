[Русский](#безопасность) | [English](#english)

# Безопасность

## Как сообщить об уязвимости

**Не открывайте публичный issue.** Сообщите закрыто через GitHub:
вкладка **Security → Report a vulnerability** этого репозитория
(private vulnerability reporting).

Полезно указать:

- версию (`reality-client --version`) или коммит;
- что именно не так и чем это грозит (утечка UUID или трафика, обход
  REALITY, отказ в обслуживании и т.п.);
- как воспроизвести — ссылку на сервер замените заглушкой, настоящие
  UUID, ключи и адреса не присылайте.

## Что считается уязвимостью

- утечка секретов (UUID, пароли, токен API) или трафика мимо прокси/TUN;
- ошибки в REALITY, XTLS Vision, TLS-проверке, из-за которых соединение
  можно прочитать, подменить или отличить от браузера;
- падение или неограниченный рост памяти от данных из сети;
- доступ к прокси, API или службе Windows без прав.

Известные ограничения перечислены в [docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md), [docs/FEATURES.md](docs/FEATURES.md) и
[PLAN.md](PLAN.md): стороннее крипто-ревью REALITY не проводилось.

## Поддерживаемые версии

Исправления выходят только для последней версии из
[Releases](https://github.com/ERGFT/vpn-core/releases) и ветки `main`.

---

<a id="english"></a>

# Security

## How to report a vulnerability

**Do not open a public issue.** Report it privately via GitHub: the
**Security → Report a vulnerability** tab of this repository (private
vulnerability reporting).

Useful to include:

- the version (`reality-client --version`) or commit;
- what exactly is wrong and what it leads to (UUID or traffic leak, REALITY
  bypass, denial of service, etc.);
- how to reproduce — replace the server link with a placeholder, do not send
  real UUIDs, keys or addresses.

## What counts as a vulnerability

- leaking secrets (UUID, passwords, API token) or traffic bypassing the
  proxy/TUN;
- bugs in REALITY, XTLS Vision or TLS verification that allow a connection to
  be read, tampered with or told apart from a browser;
- a crash or unbounded memory growth caused by data from the network;
- access to the proxy, the API or the Windows service without permission.

Known limitations are listed in [docs/SECURITY-MODEL.en.md](docs/SECURITY-MODEL.en.md), [docs/FEATURES.en.md](docs/FEATURES.en.md) and
[PLAN.md](PLAN.md) (in Russian): there has been no third-party crypto review
of REALITY.

## Supported versions

Fixes are released only for the latest version in
[Releases](https://github.com/ERGFT/vpn-core/releases) and the `main` branch.
